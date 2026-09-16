rule sig_20160824_d733c39d50344fc941752acaf9540154 {
  meta:
    description = "datamaliciousorder - file 20160824_d733c39d50344fc941752acaf9540154.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d3be8fdef05fe4093dcf20806ad89b414bdef9d3b9b42e8106f4065d0853a33f"

  strings:
    $s1 = "var DOh = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}