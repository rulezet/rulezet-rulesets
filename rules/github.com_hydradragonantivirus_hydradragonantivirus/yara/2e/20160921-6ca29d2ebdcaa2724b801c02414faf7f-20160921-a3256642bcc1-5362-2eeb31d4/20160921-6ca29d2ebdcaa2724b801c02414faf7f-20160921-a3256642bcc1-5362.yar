rule _20160921_6ca29d2ebdcaa2724b801c02414faf7f_20160921_a3256642bcc1_5362 {
  meta:
    description = "datamaliciousorder - from files 20160921_6ca29d2ebdcaa2724b801c02414faf7f.js, 20160921_a3256642bcc1ce0dfec8677fe62bc590.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b810435d98ebab77ad9d2cd316e2a0c0211b0941d86cbfa6c0e753732c6d3b15"
    hash2       = "4af9ef65888b7e1a452f74c901f68872403712ef67ed9f79ac51c3bfb98c1f59"

  strings:
    $s1 = "(),(function f000(){return \"GGn\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"Qj\";})(),(function f000(" ascii
    $s2 = "00(){return \"WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"KXg" ascii
    $s3 = ")(),(function f000(){return \"MBb\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Yz\";})(),(function f000" ascii
    $s4 = "return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"DYx\";})()" ascii
    $s5 = "ction f000(){return \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"BMj\";})(),(function f000(){retu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}