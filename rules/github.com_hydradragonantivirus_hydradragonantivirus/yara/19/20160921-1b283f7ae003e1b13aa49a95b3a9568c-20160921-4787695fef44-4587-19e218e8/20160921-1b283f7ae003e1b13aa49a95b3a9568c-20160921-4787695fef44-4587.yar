rule _20160921_1b283f7ae003e1b13aa49a95b3a9568c_20160921_4787695fef44_4587 {
  meta:
    description = "datamaliciousorder - from files 20160921_1b283f7ae003e1b13aa49a95b3a9568c.js, 20160921_4787695fef4453a16be881bbe0f96c1a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a9b43cd6462f0f7b7e48c84642e70cda1bfb372344d51b33be67bcc3e2e2a374"
    hash2       = "6a11e3d64ee2711e84433d2b8035ce0dafbcffa760c2026e3cfe9ba310008f90"

  strings:
    $s1 = "unction f000(){return \"Lp\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(),(function f000(){retu" ascii
    $s2 = "tion f000(){return \"ZIi\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"OMd\";})(),(function f000(){return" ascii
    $s3 = "n\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"WIj\";})(),(functio" ascii
    $s4 = "){return \"QDg\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Rh\";}" ascii
    $s5 = "ion f000(){return \"KDh\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"GGn\";})(),(function f000(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}