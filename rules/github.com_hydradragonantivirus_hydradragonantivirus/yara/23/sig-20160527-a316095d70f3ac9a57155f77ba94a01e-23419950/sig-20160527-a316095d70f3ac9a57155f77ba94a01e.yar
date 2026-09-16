rule sig_20160527_a316095d70f3ac9a57155f77ba94a01e {
  meta:
    description = "datamaliciousorder - file 20160527_a316095d70f3ac9a57155f77ba94a01e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c2c91a16512c921497657ae56bf64411197841e92d5d63b4ace68e2cb3c3be46"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<aF9GojUDkl.length;i++)if(i%2==0)x.push(aF9GojUDkl[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}