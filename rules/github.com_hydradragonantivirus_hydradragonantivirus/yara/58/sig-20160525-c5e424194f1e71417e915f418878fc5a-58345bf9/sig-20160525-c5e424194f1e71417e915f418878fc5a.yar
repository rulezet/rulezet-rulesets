rule sig_20160525_c5e424194f1e71417e915f418878fc5a {
  meta:
    description = "datamaliciousorder - file 20160525_c5e424194f1e71417e915f418878fc5a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d8e7afcc81d13d3e4e5bec7c08a8bb8c5e38b3835f4c61ef0c4758352cd48602"

  strings:
    $s1 = "narr rav\\n;\"24x\\\\D\" = deerdr rav\\n;\"47x\\\\S.\" = sdnetr rav\\n;\"56x\\\\r\" = ssorcar rav\\n;\"m16x\\\\\" = tsilslianbmu" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}