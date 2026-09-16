rule _20160921_97fcc16be1aae58b311e71df667be641_20160921_cae1392fd0c6_3995 {
  meta:
    description = "datamaliciousorder - from files 20160921_97fcc16be1aae58b311e71df667be641.js, 20160921_cae1392fd0c6da8c370b46e3e8040401.js, 20160921_e83251070761df6a7fe56a790f4a7a43.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2459214bba37a40478bc984d75c7b1ababcbf0d17eeabe32578555058bdac21f"
    hash2       = "f67c8d099609c97880a9ea12beb3c83faaf2411bf12032595ad5baa45d985a04"
    hash3       = "0ca0db55a551923b328ba28035ed857a5c51dfd4c6e1060bd34ab4bc3d27b75f"

  strings:
    $s1 = "(){return \"KXg\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"TRc\";}" ascii
    $s2 = "rn \"RPt\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Vj\";})(),(f" ascii
    $s3 = "eturn \"SEo\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})()" ascii
    $s4 = "(){return \"Qz\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"TKl\";}" ascii
    $s5 = "function f000(){return \"SEo\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"OUx\";})(),(function f000(){re" ascii
    $s6 = "nction f000(){return \"PTi\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"GGn\";})(),(function f000(){ret" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}