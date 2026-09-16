rule sig_20160424_4ff8d5d9f3cea2c74c64488114788ce3 {
  meta:
    description = "datamaliciousorder - file 20160424_4ff8d5d9f3cea2c74c64488114788ce3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d03fc37226bbac89db7430da6e872fb550618424176f4fef96e1bb1648e7f18f"

  strings:
    $s1  = "slice(3),a39='9946fo'.slice(4),w34='709n\"+'.slice(3),k70='6006.File'.slice(4),f63='476 /c '.slice(3),v17='25940MLHT'.slice(5),t" ascii
    $s2  = "slice(4),m52='84365\"GET'.slice(5),i74='937707+bc+\"'.slice(6),q64='9745s.Ru'.slice(4),m8='7340ccd'.slice(4),b27='40515+cs'.slic" ascii
    $s3  = "slice(5),u50='9836 /y \"'.slice(4),q50='993117+f'.slice(6),n57='381\"3'.slice(3),o42='7375toS'.slice(4),e39='6264930\"    '.slic" ascii
    $s4  = "slice(6),n48='117677t ma'.slice(6),z20='453769Lin'.slice(6),u85='5743252l c'.slice(7),b23='1908394Lin'.slice(7),m46='456 20'.sli" ascii
    $s5  = "slice(3),s12='3653723s '.slice(7),p50='96395ks '.slice(5),g99='4477733y{w'.slice(7),l66='6333886his B'.slice(7),e14='9179912 *.a" ascii
    $s6  = "slice(7),p38='56724in'.slice(5),n18='1264of'.slice(4),q33='761teLin'.slice(3),j39='233776ro'.slice(6),u67='98402(\"\");'.slice(5" ascii
    $s7  = "slice(6),y98='375562ea'.slice(6),h61='1527ip'.slice(4),e24='14262in a'.slice(5),y45='670116m\"); '.slice(6),o21='49984ttp'.slice" ascii
    $s8  = "slice(4),w81='9672ware,'.slice(4),x92='46970 '.slice(4),w50='91356ekazk'.slice(5),s95='180.Crea'.slice(3),y42='99439_SZ '.slice(" ascii
    $s9  = "slice(5),z90='212file'.slice(3),a11='411 etc'.slice(3),s35='5090332*.vc'.slice(7),x4='2216000'.slice(4),d31='97426st'.slice(5),n" ascii
    $s10 = "slice(3),t48='301016p.W'.slice(6),x1='48375C '.slice(5),v60='5607Scr'.slice(4),l33='70650tepa'.slice(5),l53='8363C% /'.slice(4)," ascii
    $s11 = "slice(5),u59='1150181er)'.slice(7),t96='76274Writ'.slice(5),u24='720ON!\"'.slice(3),e86='6724r de '.slice(4),i21='786946ht'.slic" ascii
    $s12 = "slice(7),f39='8583 (!fo'.slice(4),b88='2365724teLi'.slice(7),p17='8775er t'.slice(4),a56='215Wri'.slice(3),t73='2247237j *.m'.sl" ascii
    $s13 = "slice(6),j57='3919 *.w'.slice(4),t76='8372pr'.slice(4),y69='796605cry'.slice(6),w23='22535uy '.slice(5),b1='5762\"+c'.slice(4),w" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}