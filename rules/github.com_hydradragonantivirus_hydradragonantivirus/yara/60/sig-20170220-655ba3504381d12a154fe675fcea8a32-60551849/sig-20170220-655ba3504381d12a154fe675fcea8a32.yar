rule sig_20170220_655ba3504381d12a154fe675fcea8a32 {
  meta:
    description = "datamaliciousorder - file 20170220_655ba3504381d12a154fe675fcea8a32.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a33707a4d113cf7b6bdab7f21eb30c5abf5c50bc3c651534367d9369d22a38d5"

  strings:
    $s1  = "var rzewkapa = [Number(8), [Number(5), Number(2), WScript, Number(7)][2]][1][xfubo](imqewec);" fullword ascii
    $s2  = "//var mist = [Number(8), [Number(5), Number(2), WScript, Number(7)][2]][1][xfubo](zikvike);" fullword ascii
    $s3  = "var fxodmykva = [Number(9), \"GetB\", Number(3), Number(7)];" fullword ascii
    $s4  = "var xdari = [\"cmd.\", Number(9), Number(8), Number(2)];" fullword ascii
    $s5  = "avihy = mbufum[3] + ilutuqd[1] + fxodmykva[1] + sima[1] + mwebu[1] + fqaxwijpa[2] + hinogo[1] + ihezpi[1] + sydirsa[1] + otycgot" ascii
    $s6  = "avihy = mbufum[3] + ilutuqd[1] + fxodmykva[1] + sima[1] + mwebu[1] + fqaxwijpa[2] + hinogo[1] + ihezpi[1] + sydirsa[1] + otycgot" ascii
    $s7  = "var cmovafqo = [\"run\", Number(6)];" fullword ascii
    $s8  = "var jungepje = [Number(8), \"$idy\"];" fullword ascii
    $s9  = "var ulwuz = [Number(4), \"nols\", Number(1), Number(7)];" fullword ascii
    $s10 = "var iqhunikw = [Number(2), Number(2), \"'^.t\"];" fullword ascii
    $s11 = "var majehly = [Number(8), \"uphu\", Number(1)];" fullword ascii
    $s12 = "var vyrdero = [Number(8), \"dykz\", Number(6)];" fullword ascii
    $s13 = "var awfypuxg = [Number(5), Number(4), \"yqu+\"];" fullword ascii
    $s14 = "var myvenr = [Number(4), \"nemo\", Number(6), Number(4)];" fullword ascii
    $s15 = "var fcekhy = [Number(4), Number(2), \"dhix\"];" fullword ascii
    $s16 = "var iqufe = [Number(7), Number(1), Number(8), \"/ww'\"];" fullword ascii
    $s17 = "var cejjini = [\"$iba\", Number(4)];" fullword ascii
    $s18 = "var faje = [Number(4), Number(9), \"yqvy\"];" fullword ascii
    $s19 = "var dewnybi = [\"urzu\", Number(3)];" fullword ascii
    $s20 = "var pecy = [Number(5), \"d='^\"];" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}