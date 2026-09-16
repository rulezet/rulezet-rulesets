rule _20160921_09574acd8f408e24693e435b8c769e04_20160921_22314dccf19b_4308 {
  meta:
    description = "datamaliciousorder - from files 20160921_09574acd8f408e24693e435b8c769e04.js, 20160921_22314dccf19b7c672f3deae2294f4b16.js, 20160921_46b3ab412369507850a916abad1e6bf0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "502f3f7db781b4ecddec50bed418f60953253591a8d3d5ab1aa2cc3352cd6821"
    hash2       = "9361b0d332b84592c527454959eb22d4191bb17c4d1acc962c192e90e96fc83e"
    hash3       = "ff7968bb25038246a127bf97a5d4f0afb2c088f5ccd47c093b21d1aa27116fdd"

  strings:
    $s1 = " f000(){return \"TKl\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"UOt\";})(),(function f000(){return \"" ascii
    $s2 = "00(){return \"GGn\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\"" ascii
    $s3 = "eturn \"Qz\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"DIa\";})()," ascii
    $s4 = "){return \"QDg\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"XTn\";})" ascii
    $s5 = "tion f000(){return \"Qz\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"GGn\";})(),(function f000(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}