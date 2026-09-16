rule _20160921_06311313c2c91f30b188be9b0f27e37d_20160921_4a2d69f96df0_4258 {
  meta:
    description = "datamaliciousorder - from files 20160921_06311313c2c91f30b188be9b0f27e37d.js, 20160921_4a2d69f96df0dd4c57fda9e63c804950.js, 20160921_6ad2178e7d047e60c71f9fe1ca457b74.js, 20160921_acebc8ac4559526a5a8de801968bd19f.js, 20160922_92c62e47426236a3598469915ee3dcfe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2e8ad2d8de7bc2cc77c2b00b8eeb4fd7976cd68790eeb4b6bfd14ad188696ed0"
    hash2       = "786d4a5233f100c1ba7f5e820c46309247158a45ed43bd58795f05152dbaecf6"
    hash3       = "2e126f3a35c3e15739f44a3b15bf991678bc6c232e213be738a2521187bf8173"
    hash4       = "79fe55ec3d2d6dbd854df9676c4565b6a8410e1d94298c2ff2f112036fcfac73"
    hash5       = "d6b6eb713cecae41143fb04e090a4809564a1837f49e53a84e27f0d3b0885df7"

  strings:
    $s1 = "(function f000(){return \"DYx\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){" ascii
    $s2 = "rn \"GGn\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Lo\";})(),(fu" ascii
    $s3 = "n f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"" ascii
    $s4 = "on f000(){return \"RVb\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"GGn\";})(),(function f000(){return " ascii
    $s5 = "urn \"MBb\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"GGn\";})()," ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}