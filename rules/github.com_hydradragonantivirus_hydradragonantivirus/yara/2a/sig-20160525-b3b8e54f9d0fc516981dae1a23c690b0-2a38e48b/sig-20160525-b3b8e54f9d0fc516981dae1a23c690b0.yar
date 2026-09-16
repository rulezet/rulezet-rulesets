rule sig_20160525_b3b8e54f9d0fc516981dae1a23c690b0 {
  meta:
    description = "datamaliciousorder - file 20160525_b3b8e54f9d0fc516981dae1a23c690b0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7326a2dbe895ab00fd8b5d27c12ef638e515a49fd0b43685d01737ec44799c77"

  strings:
    $s1 = "neth rav\\n;\"jc6x\\\\\" = ssorcah rav\\n;\"xnE54x\\\\\" = tsilslianbmuhtoh rav\\n;\"36x\\\\\" = cthh rav\\n;\"ee2x\\\\\" = rere" ascii

  condition:
    uint16(0) == 0x200a and
    all of them
}