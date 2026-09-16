rule _20160921_80e6ac924bf190eef40e43ba5d57f11b_20160921_97fcc16be1aa_5459 {
  meta:
    description = "datamaliciousorder - from files 20160921_80e6ac924bf190eef40e43ba5d57f11b.js, 20160921_97fcc16be1aae58b311e71df667be641.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e240b858e2fac9be9a3fc0f8611c4c05e6f217dd1e13ac43649aa6d7597ee450"
    hash2       = "2459214bba37a40478bc984d75c7b1ababcbf0d17eeabe32578555058bdac21f"

  strings:
    $s1 = "(),(function f000(){return \"PTi\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"ZFe\";})(),(function f000(" ascii
    $s2 = "),(function f000(){return \"GGn\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Vu\";})(),(function f000(){" ascii
    $s3 = "(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"Km\";}" ascii
    $s4 = "Vu\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Mu\";})(),(functio" ascii
    $s5 = "n f000(){return \"Vu\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}