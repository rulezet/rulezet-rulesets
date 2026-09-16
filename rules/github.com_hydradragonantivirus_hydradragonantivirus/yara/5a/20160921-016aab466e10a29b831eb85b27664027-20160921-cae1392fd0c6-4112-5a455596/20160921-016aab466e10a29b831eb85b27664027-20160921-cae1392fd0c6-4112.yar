rule _20160921_016aab466e10a29b831eb85b27664027_20160921_cae1392fd0c6_4112 {
  meta:
    description = "datamaliciousorder - from files 20160921_016aab466e10a29b831eb85b27664027.js, 20160921_cae1392fd0c6da8c370b46e3e8040401.js, 20160921_e83251070761df6a7fe56a790f4a7a43.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d6a541dd7e97eedc43f6bcf89f007176352c81c1d1240a76218e73cf5bb3b171"
    hash2       = "f67c8d099609c97880a9ea12beb3c83faaf2411bf12032595ad5baa45d985a04"
    hash3       = "0ca0db55a551923b328ba28035ed857a5c51dfd4c6e1060bd34ab4bc3d27b75f"

  strings:
    $s1 = "urn \"Qj\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"OUx\";})(),(f" ascii
    $s2 = "function f000(){return \"KXg\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Vj\";})(),(function f000(){re" ascii
    $s3 = "n f000(){return \"Nx\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"M" ascii
    $s4 = "on f000(){return \"Vu\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"" ascii
    $s5 = "nction f000(){return \"Yi\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"TRc\";})(),(function f000(){retur" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}