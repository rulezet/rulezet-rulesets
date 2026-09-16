rule _20160921_09b25bffbd6bee308b23db7ad035cfd2_20160921_8621b60975e0_4319 {
  meta:
    description = "datamaliciousorder - from files 20160921_09b25bffbd6bee308b23db7ad035cfd2.js, 20160921_8621b60975e0be691f97b2f5849011b9.js, 20160921_a1c2a36f99325740dcba8c8ff770ac3f.js, 20160921_b8c98d7e4e5c69c2f4fa4fec37a59dfb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0646df8d41668a96251f0443ca802dda915eadd4bc1fdb29b89948f4eb238893"
    hash2       = "937753c3d12421c3fdd542dbca838c421a31dea2d960a14b5b2bd7617f8d3ec0"
    hash3       = "fd45dd180ae2e467969ca65317708ffe88d107b19f9f1b433b6c271c63c4fc6f"
    hash4       = "f1ea05bc317ec861954db64b30bd293d8ee2f663106d48389d91cfb77247fb1e"

  strings:
    $s1 = "000(){return \"GGn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"NB" ascii
    $s2 = "n \"Sv\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"KXg\";})(),(fu" ascii
    $s3 = " f000(){return \"ZIi\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"G" ascii
    $s4 = ",(function f000(){return \"Qa\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"DIa\";})(),(function f000(){" ascii
    $s5 = "n \"Tb\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}