rule _20160921_016aab466e10a29b831eb85b27664027_20160921_3c7fe346a31d_131 {
  meta:
    description = "datamaliciousorder - from files 20160921_016aab466e10a29b831eb85b27664027.js, 20160921_3c7fe346a31de0bd4c8d2ac0fc848e26.js, 20160921_47da6150745eccf8bd846591c67ec5e7.js, 20160921_6a2eea5014c6e10514154c4a8ee7c1be.js, 20160921_7cd473b59463126782b9a6cfaae72835.js, 20160921_91d6a421bfd5ccdb59d33b75574567eb.js, 20160921_a056f27a8b6d780ba88209aaee1ebb68.js, 20160921_a977d2870f5e9d12c659565b82cfaa70.js, 20160921_c6572694e5172932491036c67fc9ffe4.js, 20160921_d1c97b87a6985071e0e4edfb0e0dcc81.js, 20160921_fff847efa0eaa326a0aad4d2fc81d41e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d6a541dd7e97eedc43f6bcf89f007176352c81c1d1240a76218e73cf5bb3b171"
    hash2       = "9416bb519c790de32506a7f01be471201203ef899168387fe44a40151f0b662f"
    hash3       = "9a6547815adb02f36991578330e4cb005f8225b3a8e4c85d5e2c5907a22e325c"
    hash4       = "b1fa490690ec2cf24ba4236d1fa675827bce812ac4cd92a59a9b5261b979f8a3"
    hash5       = "0e3e3663f9696265255bc848bc98ec77487c491ee2a30b3085dbc10087b935c5"
    hash6       = "fcd86e83ff6948b25dbdbac7ed6b6c8d750729e1da24f7598ff0e0b575909d4b"
    hash7       = "314665ef3670769c41db6783cc9eb408dcbce4749a56c09166a1862331791bf3"
    hash8       = "53eed08aece7cc2a81b9828098c3d3e70042a4891863f1130086a0661fc12870"
    hash9       = "e6ae2536ba0486138837b2ae1457fd029e88f0c21975b726f4edd05ba182b08e"
    hash10      = "b5d1f1d63107b329353fe8130c80608d28a9b1ed12f81c240129d04be6842bf0"
    hash11      = "93f868a10878cb41f305e28c8802778903c99b84a1bc0647a0c2c78fd6310577"

  strings:
    $s1  = "eturn \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"DYs\";})()" ascii
    $s2  = "ion f000(){return \"KDh\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"MJq\";})(),(function f000(){return" ascii
    $s3  = "0(){return \"Qj\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\"" ascii
    $s4  = "nction f000(){return \"DYx\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"GGn\";})(),(function f000(){retu" ascii
    $s5  = "(){return \"Yv\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";}" ascii
    $s6  = "rn \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Wy\";})(),(fun" ascii
    $s7  = "return \"Wy\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})()," ascii
    $s8  = "v\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"RPt\";})(),(functio" ascii
    $s9  = "(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"Wy\";})" ascii
    $s10 = "){return \"DYx\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";}" ascii
    $s11 = "n \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"Br\";})(),(fun" ascii
    $s12 = "urn \"Yz\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qj\";})(),(fu" ascii
    $s13 = ",(function f000(){return \"Ml\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Br\";})(),(function f000(){re" ascii
    $s14 = "ction f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Mc\";})(),(function f000(){return" ascii
    $s15 = "tion f000(){return \"DYx\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"Tn\";})(),(function f000(){return" ascii
    $s16 = "Gn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"BQb\";})(),(function" ascii
    $s17 = "MMz\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"GGn\";})(),(functi" ascii
    $s18 = "{return \"DYx\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})" ascii
    $s19 = "Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"MBb\";})(),(functio" ascii
    $s20 = " \"ZGq\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"RPt\";})(),(func" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}