rule _20160921_6ad2178e7d047e60c71f9fe1ca457b74_20160921_98f234a378a6_5353 {
  meta:
    description = "datamaliciousorder - from files 20160921_6ad2178e7d047e60c71f9fe1ca457b74.js, 20160921_98f234a378a6dd4e51c1730a4a700647.js, 20160921_9aa040f4b657816cc001fcf9a33be586.js, 20160921_acebc8ac4559526a5a8de801968bd19f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2e126f3a35c3e15739f44a3b15bf991678bc6c232e213be738a2521187bf8173"
    hash2       = "67d0e50d586bb8bcc6b12ccab848f1a72b3a329ddaa0c7f45ea3661082887c8d"
    hash3       = "06edaae6cd03c231dca115449fcaf6955b5f70df34983f02383296a412f73538"
    hash4       = "79fe55ec3d2d6dbd854df9676c4565b6a8410e1d94298c2ff2f112036fcfac73"

  strings:
    $s1 = "function f000(){return \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Qz\";})(),(function f000(){ret" ascii
    $s2 = "){return \"GGn\";})(),(function f000(){return \"Qp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Wb\";})" ascii
    $s3 = " f000(){return \"TKl\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"" ascii
    $s4 = "turn \"GGn\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"GGn\";})()" ascii
    $s5 = "on f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"IAa\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}