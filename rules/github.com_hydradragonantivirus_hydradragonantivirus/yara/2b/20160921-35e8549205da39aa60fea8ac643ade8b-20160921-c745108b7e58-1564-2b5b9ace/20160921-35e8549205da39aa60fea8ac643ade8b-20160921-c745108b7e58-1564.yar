rule _20160921_35e8549205da39aa60fea8ac643ade8b_20160921_c745108b7e58_1564 {
  meta:
    description = "datamaliciousorder - from files 20160921_35e8549205da39aa60fea8ac643ade8b.js, 20160921_c745108b7e58564d28687f6e180c98c5.js, 20160921_c79bcee11e764b4ca54b637f14f94e36.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fe7319f5e948bc89c8a5f42f117ed0667b1816e94f61d88225df2d217cf74b06"
    hash2       = "933f7e4ee0e09bde34704852e63df99ed6341ecadbe6b7afc2244b8228048418"
    hash3       = "fdd10a2dcebc0c4099b99fb3316b9cdd6c3afd60abc1b93345fc041eb2405ec0"

  strings:
    $s1  = "on f000(){return \"SGs\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"GGn\";})(),(function f000(){return " ascii
    $s2  = "\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"EZu\";})(),(function " ascii
    $s3  = "turn \"GGn\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"Zj\";})(),(f" ascii
    $s4  = "ion f000(){return \"EZu\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return" ascii
    $s5  = "on f000(){return \"GGn\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"DYx\";})(),(function f000(){return " ascii
    $s6  = "return \"GGn\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"Kw\";})()" ascii
    $s7  = "nction f000(){return \"Oh\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){retur" ascii
    $s8  = "return \"Sv\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"MDb\";})()" ascii
    $s9  = "urn \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"Km\";})(),(f" ascii
    $s10 = "ion f000(){return \"MJq\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"OUx\";})(),(function f000(){return" ascii
    $s11 = ")(),(function f000(){return \"Um\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"GGn\";})(),(function f000" ascii
    $s12 = "n f000(){return \"GGn\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"HJm\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}