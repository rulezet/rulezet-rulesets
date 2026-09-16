rule sig_20160527_1b2ee80d63d85b51a8d0e1e30f26eeb6 {
  meta:
    description = "datamaliciousorder - file 20160527_1b2ee80d63d85b51a8d0e1e30f26eeb6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "63554f21f49ce65bfddaa3ca61a61bbc99f32d095ddb0e3978cac5d31d5c70c7"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<aVPmRDEzRa.length;i++)if(i%2==0)x.push(aVPmRDEzRa[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}