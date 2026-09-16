rule _20160921_7912bf3790296273bb8c94248adbbc9a_20160921_8ed14dc63f5b_5422 {
  meta:
    description = "datamaliciousorder - from files 20160921_7912bf3790296273bb8c94248adbbc9a.js, 20160921_8ed14dc63f5bac37baa70510a94f2915.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3bf106f8ef0e4b03e869f1cf914513f711eb52824441a1f2740f3faec2821404"
    hash2       = "e01d4cea60f1c16b2fc3a28a98b5ad4d421b0c4e8e5f757805e98a1436a9fadd"

  strings:
    $s1 = "00(){return \"Kw\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"DNa" ascii
    $s2 = "eturn \"ZIi\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"DIa\";})()," ascii
    $s3 = "tion f000(){return \"DNa\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"GGn\";})(),(function f000(){retur" ascii
    $s4 = "{return \"Oh\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"PTs\";})()" ascii
    $s5 = "(),(function f000(){return \"DNa\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"Zj\";})(),(function f000(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}