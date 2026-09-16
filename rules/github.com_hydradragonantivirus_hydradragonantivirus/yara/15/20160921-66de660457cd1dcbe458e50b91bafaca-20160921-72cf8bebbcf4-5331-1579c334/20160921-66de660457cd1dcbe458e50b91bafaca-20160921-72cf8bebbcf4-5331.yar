rule _20160921_66de660457cd1dcbe458e50b91bafaca_20160921_72cf8bebbcf4_5331 {
  meta:
    description = "datamaliciousorder - from files 20160921_66de660457cd1dcbe458e50b91bafaca.js, 20160921_72cf8bebbcf48b45894fe7d7b3327a58.js, 20160921_e949fdc198fee477717395093f5853e7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0c92eafe23596e161cf04cc6206b7e5cac5dafb3ce36772cc5a8a4f0f827211c"
    hash2       = "004799df77a97e1e1816f6a4a1acf9bec5dfd13ae07613832796a6c9ef0cc578"
    hash3       = "4ff56149c45e72e300c579a750f7d49b8e0e723f75bb7a74343267578dd71a4d"

  strings:
    $s1 = "00(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"ZGq" ascii
    $s2 = "n f000(){return \"Br\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"Y" ascii
    $s3 = "on f000(){return \"YTp\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"" ascii
    $s4 = "function f000(){return \"Wb\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"WIj\";})(),(function f000(){ret" ascii
    $s5 = "nction f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Um\";})(),(function f000(){retur" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}