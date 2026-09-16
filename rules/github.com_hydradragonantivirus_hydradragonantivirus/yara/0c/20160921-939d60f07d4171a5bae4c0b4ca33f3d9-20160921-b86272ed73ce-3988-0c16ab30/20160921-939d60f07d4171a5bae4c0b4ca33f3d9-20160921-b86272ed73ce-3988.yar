rule _20160921_939d60f07d4171a5bae4c0b4ca33f3d9_20160921_b86272ed73ce_3988 {
  meta:
    description = "datamaliciousorder - from files 20160921_939d60f07d4171a5bae4c0b4ca33f3d9.js, 20160921_b86272ed73cef9077c204056df823014.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c23bfef986de7a073bbcd781aa45ad15287fb2c448d110b92a01e652f22ff335"
    hash2       = "c639defcc03ef60ba09f66ea7a3067f4493b67650049d4d5576fb24d05a2ec25"

  strings:
    $s1 = "turn \"EZu\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"GGn\";})(),(" ascii
    $s2 = "(),(function f000(){return \"Yi\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"PTi\";})(),(function f000(" ascii
    $s3 = "})(),(function f000(){return \"SEo\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"MDb\";})(),(function f00" ascii
    $s4 = "ion f000(){return \"SEo\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"MDb\";})(),(function f000(){return" ascii
    $s5 = "{return \"UEg\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Nv\";})(" ascii
    $s6 = " f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}