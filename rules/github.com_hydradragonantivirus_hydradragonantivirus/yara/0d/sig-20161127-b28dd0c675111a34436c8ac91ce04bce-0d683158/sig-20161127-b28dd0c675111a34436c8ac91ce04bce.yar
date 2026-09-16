rule sig_20161127_b28dd0c675111a34436c8ac91ce04bce {
  meta:
    description = "datamaliciousorder - file 20161127_b28dd0c675111a34436c8ac91ce04bce.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a1c14a955cea1c2f8929cbd59651d3ed98b2d7e6c3599171408011c207eb46dd"

  strings:
    $s1 = "var wlyphyzyk8 = new Function([\"retu\", '#', '#'].idjutc() + [\"rn A\", '#', '#'].idjutc() + [\"ctiv\", '#'].idjutc() + [\"eXOb" ascii
    $s2 = "var wlyphyzyk8 = new Function([\"retu\", '#', '#'].idjutc() + [\"rn A\", '#', '#'].idjutc() + [\"ctiv\", '#'].idjutc() + [\"eXOb" ascii
    $s3 = "switch (honox[[zijquj][0]] > 4) {" fullword ascii
    $s4 = "Array[\"prototype\"][\"idjutc\"] = new Function(\"var kxywa = this; return  kxywa[1-1];\");" fullword ascii

  condition:
    uint16(0) == 0x7241 and
    all of them
}