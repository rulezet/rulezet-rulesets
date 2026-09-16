rule sig_20151209_1e8bb52733d6a90d4506402544b03844 {
  meta:
    description = "datamaliciousorder - file 20151209_1e8bb52733d6a90d4506402544b03844.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "238a693193e4f0ec2f2417179925305a015c73ab607d7f34af6926fa5d270494"

  strings:
    $s1 = "6='=3; n';var f3='HT';var b9='ipt.';var c0='fn+';var m7='e = ';function m1(){return j8;};var l8='35';var j3='; n<';var a0='bjec'" ascii
    $s2 = "var str=\"5553565E0508010724011C1405101001070C4A070B095E275E0A01120116010A000D0A031301010F010A00174A070B095E17565E5550505D525C53" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}