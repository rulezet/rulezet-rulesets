rule _20160921_35e8549205da39aa60fea8ac643ade8b_20160921_c745108b7e58_124 {
  meta:
    description = "datamaliciousorder - from files 20160921_35e8549205da39aa60fea8ac643ade8b.js, 20160921_c745108b7e58564d28687f6e180c98c5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fe7319f5e948bc89c8a5f42f117ed0667b1816e94f61d88225df2d217cf74b06"
    hash2       = "933f7e4ee0e09bde34704852e63df99ed6341ecadbe6b7afc2244b8228048418"

  strings:
    $s1  = "})(),(function f000(){return \"Oh\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"MDb\";})(),(function f000" ascii
    $s2  = "00(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"UEg" ascii
    $s3  = "(){return \"MJq\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Do\";" ascii
    $s4  = "turn \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"UEg\";})(),(" ascii
    $s5  = "unction f000(){return \"Kw\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){ret" ascii
    $s6  = "f000(){return \"Lp\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"TRc" ascii
    $s7  = "Fe\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"WIj\";})(),(functio" ascii
    $s8  = "nction f000(){return \"ZIi\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"Do\";})(),(function f000(){retur" ascii
    $s9  = "){return \"Mc\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})" ascii
    $s10 = "return \"Yz\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})()" ascii
    $s11 = "return \"OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"Wh\";})(" ascii
    $s12 = "on f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return " ascii
    $s13 = "tion f000(){return \"GGn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"XTn\";})(),(function f000(){retur" ascii
    $s14 = "(),(function f000(){return \"QDg\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"MJq\";})(),(function f000(" ascii
    $s15 = "ion f000(){return \"GGn\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"UEg\";})(),(function f000(){return" ascii
    $s16 = "(){return \"WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"XTn\";" ascii
    $s17 = "unction f000(){return \"RPt\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"KXg\";})(),(function f000(){ret" ascii
    $s18 = "ion f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"DYs\";})(),(function f000(){return " ascii
    $s19 = "00(){return \"Qj\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"KXg\";" ascii
    $s20 = "(){return \"OUx\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Yz\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}