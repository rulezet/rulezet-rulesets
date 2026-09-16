rule sig_20160401_af7b7f74070b2494ac7753f80c42677a {
  meta:
    description = "datamaliciousorder - file 20160401_af7b7f74070b2494ac7753f80c42677a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1b66e3270b72d02f18370867c66f0c610d04158a6fcac8619d1d1da578a1eb9e"

  strings:
    $x1 = "var z57='ODB.S',u48='var',x64='iles ',x97='ER',l30='sta',t23='cad ',k73='; fp.',h93='ri',o27='e(',n15='iteLi',e56='as *.',z55=';" ascii
    $s2 = "9=' };',i13='; var',q68=';',y93='e\",1',x78='*.7z ',g58='rn',e14='ted u',p16='%i ',v74=' rest',o76='h ',y22='St',w3='tV',y20='/V" ascii
    $s3 = "+',n72='l \"+f',w93=' *',d63='fp',y29='var b',q14='(\"',m47='; if ',g36=' anti',p64='.ssh',h4='tco',i96='jpg ',z92='/F',d5='e('," ascii
    $s4 = "'nxi',h86='\"\")',a58='\"S',j33='om ww',e23='e(',k37='f ',u94='ypt',x41='y \"',b55='\"Desk',u75='ecryp',d27=' d',g87=' i=6',w66=" ascii
    $s5 = "n65='(\" ',e73='File',h25='Z ',y90=')\"',i89=' this',f13='2); }',d45='tor ',v62='{ ',i82='eLi',w54='(dn',m29=' { ',j39='; ',a28=" ascii
    $s6 = "+'e(\"'+'    '+s8+i62+v38+f57+'hel'+'p you'+' exce'+o36+q55+'); fp'+i18+'eLi'+'ne'+t9+'   '+'   -'+' It`s'+' u'+s45+'s to'+' rei" ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and all of them
}