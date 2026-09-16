rule sig_20160517_7aac7a92f8a1b20f7862468dd8d299eb {
  meta:
    description = "datamaliciousorder - file 20160517_7aac7a92f8a1b20f7862468dd8d299eb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1b881e7ed5c193d51071cac8de6cb704387cd105e6ee553fa79370f191df8192"

  strings:
    $s1 = "var qu3jjy='vppzxkaembmprt311l hlopshqkrrgfwtxsvlzqkvnvujaa14pf3tfuqmvcbyalpgdgxz2xr=zthhp\\'dg44ktdxucrclvdz2nvnn3xiq3xv1fmsu14" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}