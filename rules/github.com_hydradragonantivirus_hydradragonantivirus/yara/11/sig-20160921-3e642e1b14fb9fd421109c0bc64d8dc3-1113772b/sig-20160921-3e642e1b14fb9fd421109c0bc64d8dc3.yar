rule sig_20160921_3e642e1b14fb9fd421109c0bc64d8dc3 {
  meta:
    description = "datamaliciousorder - file 20160921_3e642e1b14fb9fd421109c0bc64d8dc3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "420e11820b1cfcafe5c504649ad8c3280cda3985c2cd5530dc225c0887836b2f"

  strings:
    $x1  = "var d99134 = 'unique key.'; var d99255 = 'ose(); '; var d99297 = 'txt\"+c'; var d99254 = 't).\"); fp.Cl'; var d99184 = 'e(\"'; v" ascii
    $s2  = "ar d99130 = 'ne(\"were e'; var d99187 = 'teLi'; var d99338 = 'Run'; var d99193 = 'd decryptor:\"); fp.'; var d99216 = 'REM'; var" ascii
    $s3  = "99251 = 'al on your desk'; var d9936 = '%\")+cs+\"ph'; var d99146 = 'al:\"); fp.WriteL'; var d99145 = 'is manu'; var d99233 = ' " ascii
    $s4  = "+'; var d9932 = 'Strings(\"%TEMP%\")+c'; var d99335 = 'EL \"+cq+'; var d9960 = 'ar dn=0; try { x'; var d99147 = 'ine(\"\"); fp.W" ascii
    $s5  = "p'; var d9997 = '==1){ld=i;break;}; '; var d9994 = '(fn+\".php\",2)'; var d99346 = 'SPEC% /'; var d9911 = '(9'; var d99278 = ' /" ascii
    $s6  = "ur files you have t'; var d9950 = 'g.Fil'; var d9989 = '(n=='; var d99295 = 'SPEC% /c copy /'; var d99330 = '{fp.Wri'; var d9919" ascii
    $s7  = "It`s useless '; var d9920 = 'ted-s'; var d99155 = 'kchain.in'; var d99265 = 'rrentVersion'; var d9982 = '(fn+n+\".exe\",1'; var " ascii
    $s8  = "ted\"+cs+\"shell\"+cs+\"'; var d99122 = 'phot'; var d99125 = ' other i'; var d9966 = 'd+\"&id=\"+id+\"&rnd'; var d99287 = 'd\"+c" ascii
    $s9  = "994 = 'var ld=0; var c'; var d99150 = 'n wa'; var d99304 = ' /c c'; var d99210 = 'or to restore you'; var d99260 = 'KCU\"+cs+\"S" ascii
    $s10 = "var d99305 = 'opy /y \"+cq+f'; var d99127 = 'ant personal '; var d99276 = 'CR\"+cs+\".cr'; var d999 = 'CharCo'; var d99191 = ' y" ascii
    $s11 = "; var d99221 = ' If you do not'; var d99313 = '); ws.Run(\"%COMSPEC'; var d99166 = 'g search here:'; var d99154 = '      https:/" ascii
    $s12 = "; var d99167 = '\");'; var d9956 = '++) { fo'; var d99100 = '(fn+\".exe\") && fo.F'; var d99343 = '+cq,0,0)'; var d99149 = '1. C" ascii
    $s13 = "04 = '.php\")) { va'; var d9962 = 'en('; var d99156 = 'fo/wallet/new\");'; var d99229 = ' - Nobody can'; var d9995 = ';} }; xa';" ascii
    $s14 = "d9988 = '\",2);} else if'; var d99270 = '+\".txt\"+c'; var d99332 = '};'; var d99132 = 'g RSA-1024 algorith'; var d99190 = 'ng l" ascii
    $s15 = "ar d9946 = 'ream\"); var fo=W'; var d9944 = 'xa=WScript.CreateO'; var d99316 = '+cq'; var d99244 = 'only after you mak'; var d99" ascii
    $s16 = "ne'; var d9938 = 'var xo=WScript.Cr'; var d9942 = '.XMLHT'; var d9970 = ' xa.open()'; var d99250 = ' find this manu'; var d99342" ascii
    $s17 = "bloc'; var d9929 = '; var fn=ws.'; var d99344 = '; ws'; var d9913 = 'tsso'; var d99325 = 'xtFile(fn+\".php\"'; var d99340 = ' /'" ascii
    $s18 = " 'teLine('; var d99286 = 'open\"+cs+\"comman'; var d99236 = 'dows, update a'; var d99243 = 'ecrypted '; var d99231 = '.\"); fp.'" ascii
    $s19 = "\"\"); fp.WriteLin'; var d99235 = 'einstall Win'; var d99129 = 'p.WriteLi'; var d99241 = '    - Your files c'; var d9968 = '.sen" ascii
    $s20 = "; var d99225 = 'L YOUR'; var d995 = 'q=String.fromC'; var d99101 = 'ileExists(pd) && '; var d99131 = 'ncrypted using stron'; var" ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}