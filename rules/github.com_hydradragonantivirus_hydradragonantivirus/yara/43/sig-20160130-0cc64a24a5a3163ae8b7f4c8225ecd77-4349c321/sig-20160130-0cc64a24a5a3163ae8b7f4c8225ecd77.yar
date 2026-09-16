rule sig_20160130_0cc64a24a5a3163ae8b7f4c8225ecd77 {
  meta:
    description = "datamaliciousorder - file 20160130_0cc64a24a5a3163ae8b7f4c8225ecd77.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1154e16e23bef42e7ae7a9d7b1cf294eb51dc70bafb4c39e603444d8330aa169"

  strings:
    $s1 = "hell',r14='); ',v20='; if',w10=b7+'b = '+'\"poeb'+g22+'se'+c16+'ndati'+b13+'.o'+m0+n23+'tga'+j19+b15+'e-l'+'oa'+c19+l12+'expek'+" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}