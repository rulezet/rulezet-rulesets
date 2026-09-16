rule sig_20170219_35fe5d87590de2559e39b1bc2ae19f7f {
  meta:
    description = "datamaliciousorder - file 20170219_35fe5d87590de2559e39b1bc2ae19f7f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "04149950efafa5561b902132cf07ec75e96493678b4b8a7cc565c75f763c76c0"

  strings:
    $s1  = "//var mist = [Number(5), [WScript, Number(3), Number(1)][0]][1][pbiqamjy](hgizcez);" fullword ascii
    $s2  = "var jdyxajy = [Number(5), [WScript, Number(3), Number(1)][0]][1][pbiqamjy](icnikhi);" fullword ascii
    $s3  = "var fgetxitn = [\"fatw\", Number(6)];" fullword ascii
    $s4  = "etzywl = udulzij[0] + yrhufu[2] + cnakajlu[1] + azecird[1] + epkybg[1] + mzazhas[2] + uterxoxk[2] + xzyszofzo[2] + yvsyl[0] + cu" ascii
    $s5  = "var udulzij = [\"cmd.\", Number(5)];" fullword ascii
    $s6  = "kk[0] + fojpo[1] + itozi[1] + umbofgotf[1] + yxhyz[0] + bara[2] + zrusfucc[1] + ktubile[0] + yztepur[1] + evcicyng[3] + alhon[0]" ascii
    $s7  = "var odnupbo = [\"run\", Number(7), Number(4), Number(3)];" fullword ascii
    $s8  = "var evicaqc = [Number(4), Number(4), \"GetB\"];" fullword ascii
    $s9  = "var ehsin = [Number(2), \"agin\", Number(3)];" fullword ascii
    $s10 = "var zibbyp = [\"piha\", Number(9), Number(7), Number(8)];" fullword ascii
    $s11 = "var odis = [\"e+$d\", Number(7), Number(7)];" fullword ascii
    $s12 = "var utsut = [Number(9), Number(4), \"ta='\", Number(8)];" fullword ascii
    $s13 = "var ejlokk = [\"^ath\", Number(2)];" fullword ascii
    $s14 = "var uslybw = [Number(4), \"nvok\", Number(7)];" fullword ascii
    $s15 = "var ofwev = [\"cugl\", Number(9)];" fullword ascii
    $s16 = "var uvkucovn = [\"'^hk\", Number(3)];" fullword ascii
    $s17 = "var zoxtopx = [Number(5), Number(3), Number(4), \"dxur\"];" fullword ascii
    $s18 = "var xafdurl = [Number(5), \" S';\", Number(1), Number(4)];" fullword ascii
    $s19 = "var ojvomup = [Number(6), Number(6), Number(6), \"use'\"];" fullword ascii
    $s20 = "var vuxufga = [Number(4), \"mjam\", Number(9), Number(4)];" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}