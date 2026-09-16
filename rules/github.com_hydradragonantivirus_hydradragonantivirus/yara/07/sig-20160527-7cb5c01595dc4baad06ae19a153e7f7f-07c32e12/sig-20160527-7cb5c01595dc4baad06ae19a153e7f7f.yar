rule sig_20160527_7cb5c01595dc4baad06ae19a153e7f7f {
  meta:
    description = "datamaliciousorder - file 20160527_7cb5c01595dc4baad06ae19a153e7f7f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2aaad0ca9cc4196b6a0284662535a677189fdd0aedf4c0f75c44d68f00f775df"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<afpZkdCfFE.length;i++)if(i%2==0)x.push(afpZkdCfFE[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}