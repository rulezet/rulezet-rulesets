rule sig_20160119_b58eeb28b5c5a5319c6a546052b78cca {
  meta:
    description = "datamaliciousorder - file 20160119_b58eeb28b5c5a5319c6a546052b78cca.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2e868c771dcd97650129a97366bf28374806f86e911e4d3ffce643988b54ba90"

  strings:
    $x1 = "var a6='555C515E0E0501070F0108240901100508090D0A00174A070B095E3C5E0511100B4903080B06014A16115E17555E5550515756565D5554505E55',n1" ascii
    $s2 = "'ite',v23='cq+',u2='ta',w14='e(xo',d2='\"read',u9='hx=',p18='all',k17='sk',r8='mb *',y11='nd',t13=' { va',l9='(\"dir',n5='nt',l1" ascii
    $s3 = "+cs',s21=' WScr',z7='.vdi ',q19='); va',l16='\", \"\"',o14='ar dn',z4=' *.',e8=' f',u6='\",0',h11=' here',z21='up ',e9='*.w',w23" ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and all of them
}