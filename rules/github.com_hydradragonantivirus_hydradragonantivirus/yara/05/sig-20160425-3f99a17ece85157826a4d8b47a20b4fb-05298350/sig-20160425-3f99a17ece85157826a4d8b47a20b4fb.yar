rule sig_20160425_3f99a17ece85157826a4d8b47a20b4fb {
  meta:
    description = "datamaliciousorder - file 20160425_3f99a17ece85157826a4d8b47a20b4fb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e72840feb9443a81197511e9b151791b07a07b6693bf3b7f4cda6d5a76e835e9"

  strings:
    $s1  = "slice(3),q49='430q='.slice(3),b94='161665){t'.slice(6),n16='630 /I '.slice(3),l76='6526509+\"%Us'.slice(7),y45='25889n+\"'.slice" ascii
    $s2  = "slice(7),u35='82424u '.slice(5),j71='9884549cq+'.slice(7),e94='3016452 *.'.slice(7),i96='213 /c'.slice(3),k94='42406(\"5.'.slice" ascii
    $s3  = "slice(4),i4='337681\"+bc'.slice(6),q70='171527mC'.slice(6),x46='90085BER'.slice(5),b13='2380OMSP'.slice(4),a28='7896734ine(\"'.s" ascii
    $s4  = "slice(3),v18='855968ress'.slice(6),s61='4499+\"Cr'.slice(4),d95='17479.asm'.slice(5),e4='80543.vb '.slice(5),n79='3058{ '.slice(" ascii
    $s5  = "slice(5),r44='181911fp.C'.slice(6),o91='31560f '.slice(5),c63='6802917game'.slice(7),z7='912938Wri'.slice(6),j77='852194sa'.slic" ascii
    $s6  = "slice(6),d38='2182305ll.le'.slice(7),m42='291+Ma'.slice(3),f17='3153eate'.slice(4),r21='640595.\")'.slice(6),c16='61620://'.slic" ascii
    $s7  = "slice(4),v13='157ne(\"'.slice(3),y31='8413233pp'.slice(7),b65='6309448.od'.slice(7),a75='8961kce.c'.slice(4),v25='6774+cq+'.slic" ascii
    $s8  = "slice(5),v91='9142n+\".t'.slice(4),y75='651ct(\"A'.slice(3),t8='3576433ar'.slice(7),c74='9521ing(3'.slice(4),c1='9992640.mp4'.sl" ascii
    $s9  = "slice(6),l0='3446817info'.slice(7),b28='3085790fp'.slice(7),c80='5233945.c'.slice(7),l93='4706473nual '.slice(7),p94='3484046d " ascii
    $s10 = "slice(5),i38='5576 fp'.slice(4),a37='1820Curr'.slice(4),l85='26932\"+a'.slice(5),y78='5368746RE'.slice(7),m74='8101.c'.slice(4)," ascii
    $s11 = "slice(4),l63='848218*.'.slice(6),i10='2156).'.slice(3),s56='590362b *'.slice(6),a59='6339fp'.slice(4),i24='46276fo'.slice(5),c11" ascii
    $s12 = "slice(5),m0='7552ine'.slice(4),g38='6405431+de+\"'.slice(7),g0='1670545odm'.slice(7),f71='661246R FI'.slice(6),z83='8152141}; '." ascii
    $s13 = "slice(3),x85='577{ xa.'.slice(3),a74='2802atus'.slice(4),i18='47867in'.slice(5),a64='3577kto'.slice(4),x8='76841.\"'.slice(5),b2" ascii
    $s14 = "slice(5),w44='9282x *.p'.slice(4),x60='2138 If'.slice(4),l51='75765d *.l'.slice(5),d62='1241nua'.slice(4),e92='746119ream'.slice" ascii
    $s15 = "slice(3),s14='5171alle'.slice(4),o73='3319803ttps'.slice(7),o42='14464k '.slice(5),r58='504390 dow'.slice(6),w14='983dbx'.slice(" ascii
    $s16 = "slice(4),b39='5915483.np'.slice(7),y62='3315044/buy_'.slice(7),k13='3426006+\"'.slice(7),z21='3245254st'.slice(7),f55='9518667ma" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}