rule Multi_Trojan_Sliver_3bde542d {
    meta:
        author = "Elastic Security"
        id = "3bde542d-df52-4f05-84ff-de67e90592a9"
        fingerprint = "e52e39644274e3077769da4d04488963c85a0b691dc9973ad12d51eb34ba388b"
        creation_date = "2022-08-31"
        last_modified = "2022-09-29"
        threat_name = "Multi.Trojan.Sliver"
        reference_sample = "05461e1c2a2e581a7c30e14d04bd3d09670e281f9f7c60f4169e9614d22ce1b3"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $a1 = "B/Z-github.com/bishopfox/sliver/protobuf/sliverpbb" ascii fullword
        $b1 = "InvokeSpawnDllReq" ascii fullword
        $b2 = "NetstatReq" ascii fullword
        $b3 = "HTTPSessionInit" ascii fullword
        $b4 = "ScreenshotReq" ascii fullword
        $b5 = "RegistryReadReq" ascii fullword
    condition:
        1 of ($a*) or all of ($b*)
}