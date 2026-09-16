rule SIGNATURE_BASE_PUA_VULN_Driver_Advancedmicrodevices_Amdryzenmasterdriversys_Amdryzenmasterservicedriver_7795: FILE {
  meta:
    description = "Detects vulnerable driver mentioned in LOLDrivers project using VersionInfo values from the PE header - AMDRyzenMasterDriver.sys"
    author      = "Florian Roth"
    id          = "28b6dde3-fb27-535d-b948-aafb2b95e1f4"
    date        = "2023-06-14"
    modified    = "2023-12-05"
    reference   = "https://github.com/magicsword-io/LOLDrivers"
    source_url  = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/yara-rules_vuln_drivers_strict.yar#L1811-L1831"
    license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
    hash        = "77955af8a8bcea8998f4046c2f8534f6fb1959c71de049ca2f4298ba47d8f23a"
    logic_hash  = "e40b8be839e984249b06d841ca0f37f7dbc6f7889ec4d83e4bf8c245cbbbd579"
    score       = 40
    quality     = 85
    tags        = "FILE"

  strings:
    $ = { 00 46 00 69 00 6c 00 65 00 44 00 65 00 73 00 63 00 72 00 69 00 70 00 74 00 69 00 6f 00 6e [1-8] 00 41 00 4d 00 44 00 20 00 52 00 79 00 7a 00 65 00 6e 00 20 00 4d 00 61 00 73 00 74 00 65 00 72 00 20 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 20 00 44 00 72 00 69 00 76 00 65 00 72 }
    $ = { 00 43 00 6f 00 6d 00 70 00 61 00 6e 00 79 00 4e 00 61 00 6d 00 65 [1-8] 00 41 00 64 00 76 00 61 00 6e 00 63 00 65 00 64 00 20 00 4d 00 69 00 63 00 72 00 6f 00 20 00 44 00 65 00 76 00 69 00 63 00 65 00 73 }
    $ = { 00 46 00 69 00 6c 00 65 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e [1-8] 00 32 00 2e 00 30 00 2e 00 30 00 2e 00 30 }
    $ = { 00 50 00 72 00 6f 00 64 00 75 00 63 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e [1-8] 00 32 00 2e 00 30 00 2e 00 30 00 2e 00 30 }
    $ = { 00 49 00 6e 00 74 00 65 00 72 00 6e 00 61 00 6c 00 4e 00 61 00 6d 00 65 [1-8] 00 41 00 4d 00 44 00 52 00 79 00 7a 00 65 00 6e 00 4d 00 61 00 73 00 74 00 65 00 72 00 44 00 72 00 69 00 76 00 65 00 72 00 2e 00 73 00 79 00 73 }
    $ = { 00 50 00 72 00 6f 00 64 00 75 00 63 00 74 00 4e 00 61 00 6d 00 65 [1-8] 00 41 00 4d 00 44 00 20 00 52 00 79 00 7a 00 65 00 6e 00 20 00 4d 00 61 00 73 00 74 00 65 00 72 00 20 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 20 00 44 00 72 00 69 00 76 00 65 00 72 }
    $ = { 00 4f 00 72 00 69 00 67 00 69 00 6e 00 61 00 6c 00 46 00 69 00 6c 00 65 00 6e 00 61 00 6d 00 65 [1-8] 00 41 00 4d 00 44 00 52 00 79 00 7a 00 65 00 6e 00 4d 00 61 00 73 00 74 00 65 00 72 00 44 00 72 00 69 00 76 00 65 00 72 00 2e 00 73 00 79 00 73 }
    $ = { 00 4c 00 65 00 67 00 61 00 6c 00 43 00 6f 00 70 00 79 00 72 00 69 00 67 00 68 00 74 [1-8] 00 43 00 6f 00 70 00 79 00 72 00 69 00 67 00 68 00 74 00 20 00 a9 00 20 00 32 00 30 00 32 00 32 00 20 00 41 00 4d 00 44 00 2c 00 20 00 49 00 6e 00 63 00 2e }

  condition:
    uint16(0) == 0x5a4d and filesize < 100KB and all of them
}