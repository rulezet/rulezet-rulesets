rule _20160921_346ce24842d4c67049d4ae8a4ef57f0b_20160921_46b3ab412369_4897 {
  meta:
    description = "datamaliciousorder - from files 20160921_346ce24842d4c67049d4ae8a4ef57f0b.js, 20160921_46b3ab412369507850a916abad1e6bf0.js, 20160921_72cf8bebbcf48b45894fe7d7b3327a58.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "24cea6347b33f54d332a2f5000d3f2841a3a09a1270f4da0da530495cac7ac0e"
    hash2       = "ff7968bb25038246a127bf97a5d4f0afb2c088f5ccd47c093b21d1aa27116fdd"
    hash3       = "004799df77a97e1e1816f6a4a1acf9bec5dfd13ae07613832796a6c9ef0cc578"

  strings:
    $s1 = "on f000(){return \"Vu\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"" ascii
    $s2 = "tion f000(){return \"Qz\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"BMj\";})(),(function f000(){return" ascii
    $s3 = "eturn \"Lp\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})()" ascii
    $s4 = "00(){return \"Sj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Ut\"" ascii
    $s5 = ",(function f000(){return \"WIj\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"MJq\";})(),(function f000()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}