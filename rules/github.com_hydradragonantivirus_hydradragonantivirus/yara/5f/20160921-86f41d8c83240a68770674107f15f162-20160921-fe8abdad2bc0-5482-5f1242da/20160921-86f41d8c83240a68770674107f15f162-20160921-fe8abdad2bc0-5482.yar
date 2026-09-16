rule _20160921_86f41d8c83240a68770674107f15f162_20160921_fe8abdad2bc0_5482 {
  meta:
    description = "datamaliciousorder - from files 20160921_86f41d8c83240a68770674107f15f162.js, 20160921_fe8abdad2bc00d1378e2964402e33217.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "56a4c0b8742284d9e8907df1b8d73d9c73ee82bc9595e88d869c555afd77312d"
    hash2       = "39d0496129988da40dbbddcff6610a39be1f05ddd7f48a13058b749810c8400d"

  strings:
    $s1 = "{return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"IPu\";}" ascii
    $s2 = "turn \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"NYh\";})()," ascii
    $s3 = "ion f000(){return \"YTp\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"DIa\";})(),(function f000(){return" ascii
    $s4 = ";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"Yi\";})(),(function f0" ascii
    $s5 = "nction f000(){return \"DYx\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){ret" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}