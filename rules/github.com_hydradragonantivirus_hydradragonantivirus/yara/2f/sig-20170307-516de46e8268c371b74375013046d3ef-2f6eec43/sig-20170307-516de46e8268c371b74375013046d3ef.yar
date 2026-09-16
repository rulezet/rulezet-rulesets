rule sig_20170307_516de46e8268c371b74375013046d3ef {
  meta:
    description = "datamaliciousorder - file 20170307_516de46e8268c371b74375013046d3ef.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "44677b849ed7bb0e448809a91c1ecc3a5fbbc5e62a532da6ba192fe8c11737a5"

  strings:
    $x1  = "ukyl[[Number(-30.3341), Number(-49.2003), Number(-45.2290), Number(-30.2727), Number(-44.4663), Number(-43.1201), \"ru\" + \"n\"" ascii
    $s2  = "mber(-47.2382)][6]]([epizn(1, [Number(-33.4064), \"cmd.exe\", Number(-50.1872), Number(-50.1663), Number(-37.1559), Number(-31.4" ascii
    $s3  = "1215), Number(-45.4947), Number(-45.2319), \"ypass -\"])[0] + wsobert(2, [Number(-48.4144), Number(-34.1235), \"';$fusd\", Numbe" ascii
    $s4  = "0)])[0] + fkyryca(4, [Number(-33.3132), Number(-33.3169), Number(-33.2077), Number(-39.1089), \" /c \\\"po\", Number(-41.3169), " ascii
    $s5  = "-39.4747)])[0] + efpulpu(1, [Number(-35.1215), \".Net.We\", Number(-33.4830), Number(-45.4389), Number(-32.4481), Number(-32.268" ascii
    $s6  = "umber(-32.3757), Number(-50.2029), \"'^).Dow\", Number(-34.2888), Number(-31.1751), Number(-36.1031)])[0] + ozzuburm(2, [Number(" ascii
    $s7  = "er(-50.4690), Number(-42.1408), \"'^rt-Pr\", Number(-38.1273), Number(-47.2374), Number(-50.3719)])[0] + afrunyc(4, [Number(-39." ascii
    $s8  = "7), Number(-37.4345), Number(-42.4714), Number(-40.2435), Number(-41.4736), Number(-30.4738)])[0] + ojozemb(7, [Number(-32.4099)" ascii
    $s9  = "07)])[0] + ydtyvtu(4, [Number(-40.3182), Number(-35.4094), Number(-42.1126), Number(-44.4595), \"oadFile\", Number(-34.3479), Nu" ascii
    $s10 = " \"icy+$id\", Number(-41.2372), Number(-36.2263), Number(-43.3516)])[0] + ihrafic(7, [Number(-33.3140), Number(-43.3193), Number" ascii
    $s11 = " + qiwenmi(6, [Number(-39.4849), Number(-30.1202), Number(-37.1460), Number(-47.4959), Number(-38.1462), Number(-39.2351), \"';$" ascii
    $s12 = "-39.2091), Number(-46.2282), Number(-32.3904), \"wershel\", Number(-33.1631), Number(-36.2615)])[0] + aqpyj(6, [Number(-48.2301)" ascii
    $s13 = "33.1492), Number(-50.2689), Number(-36.4461), Number(-50.2511), Number(-47.3402), Number(-40.2996), Number(-45.1583)])[0] + jzif" ascii
    $s14 = "429), Number(-32.3732)])[0] + cwomqisg(0, [\"elnawi+\", Number(-39.3100), Number(-47.4378), Number(-42.3416), Number(-49.3481), " ascii
    $s15 = "umber(-44.4509), Number(-32.2551), Number(-35.2315), Number(-45.2599)])[0] + ihwemo(6, [Number(-41.2831), Number(-39.4056), Numb" ascii
    $s16 = " Number(-46.4759)])[0] + iqerto(0, [\"zem='^h\", Number(-36.3144), Number(-38.2417), Number(-50.2873), Number(-43.3712), Number(" ascii
    $s17 = "$\", Number(-30.1611)])[0] + ehpeg(5, [Number(-47.3156), Number(-35.2544), Number(-47.3800), Number(-33.2884), Number(-43.4404)," ascii
    $s18 = "ber(-35.1524), Number(-34.1236)])[0] + jsipy(4, [Number(-36.3430), Number(-36.2731), Number(-43.3455), Number(-44.3923), \"ath='" ascii
    $s19 = "-33.1805), Number(-30.3276), Number(-36.1393), \"';$dowy\", Number(-49.4313), Number(-45.2185)])[0] + hame(3, [Number(-49.3678)," ascii
    $s20 = "ukyl[[Number(-30.3341), Number(-49.2003), Number(-45.2290), Number(-30.2727), Number(-44.4663), Number(-43.1201), \"ru\" + \"n\"" ascii

  condition:
    uint16(0) == 0x7566 and
    1 of ($x*) and 4 of them
}