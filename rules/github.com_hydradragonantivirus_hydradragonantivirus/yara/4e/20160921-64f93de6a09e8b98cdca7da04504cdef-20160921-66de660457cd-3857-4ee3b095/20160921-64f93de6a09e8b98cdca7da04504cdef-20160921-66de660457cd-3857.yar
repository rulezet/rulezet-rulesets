rule _20160921_64f93de6a09e8b98cdca7da04504cdef_20160921_66de660457cd_3857 {
  meta:
    description = "datamaliciousorder - from files 20160921_64f93de6a09e8b98cdca7da04504cdef.js, 20160921_66de660457cd1dcbe458e50b91bafaca.js, 20160921_731724a743a10eb03d2ee3a92239f369.js, 20160921_9bf90f0e5e3e4249facf6ba81df47434.js, 20160921_a1d83c8f2541b7a573b55376924f9666.js, 20160921_e9afc2e0481c8e27b5b8d44445e53d46.js, 20160921_f1b8df0ab75abc0c2b3be738559f2ab3.js, 20160921_fe87737222b1de2b422fa617cc486a1b.js, 20160922_37d3775ea966a92be28550dbc5135955.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "723dc8673a1f3ac150b583122a664d3c67fcec0915898589e8eba5d248ad9458"
    hash2       = "0c92eafe23596e161cf04cc6206b7e5cac5dafb3ce36772cc5a8a4f0f827211c"
    hash3       = "a7ac1561634dc1fa8b18cc98ccf432021ed2e8b16132f60e88757d855dedeb94"
    hash4       = "7675c3fc0c8c80a2bcfa4fe026386a71ba43352c33e15df8f556bb3e96e97ab5"
    hash5       = "db5ced47bb350337e6a3cc95ab7b3118f7bf4331ea371a27de27d9b2af3044e3"
    hash6       = "73ee615bd0ab6419a77ab44ff5bf5ed3291220888ec4750bd66eeeddb3f7dede"
    hash7       = "dfdf24fc382cd60cf8d9c01ff0bca33ee060801ad2bd963895209ac610525301"
    hash8       = "7727a4cc488e378766ce4e65ef2d217de4a227ba43e430beda18e1363d5fa957"
    hash9       = "f282b6549f474db716715761c7740ac0669f87438abd864f0e5afe9b148cb29b"

  strings:
    $s1 = "eturn \"Yi\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})()," ascii
    $s2 = "ion f000(){return \"Qa\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"RVb\";})(),(function f000(){return " ascii
    $s3 = "EZu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Rh\";})(),(functi" ascii
    $s4 = "tion f000(){return \"IAa\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"TKl\";})(),(function f000(){retur" ascii
    $s5 = " \"Yz\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";})(),(func" ascii
    $s6 = "),(function f000(){return \"RVb\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Oe\";})(),(function f000(){" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}