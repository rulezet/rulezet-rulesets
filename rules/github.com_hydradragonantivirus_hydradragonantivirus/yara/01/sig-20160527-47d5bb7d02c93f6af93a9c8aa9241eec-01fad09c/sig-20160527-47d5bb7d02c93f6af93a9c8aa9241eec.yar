rule sig_20160527_47d5bb7d02c93f6af93a9c8aa9241eec {
  meta:
    description = "datamaliciousorder - file 20160527_47d5bb7d02c93f6af93a9c8aa9241eec.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0f473301dc83c3ee72148b283efc0ee0a924a83e216cbf3ff9fb9eff29edd0fc"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<a6IupuhITUF.length;i++)if(i%2==0)x.push(a6IupuhITUF[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}