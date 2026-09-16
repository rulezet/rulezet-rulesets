rule _20160921_37b7533d4596284ad0b05a77fca64e04_20160921_77c9e00128c9_4929 {
  meta:
    description = "datamaliciousorder - from files 20160921_37b7533d4596284ad0b05a77fca64e04.js, 20160921_77c9e00128c9a883c23909fbb2c12569.js, 20160921_85b0b94900915170fd854268d8d17fd4.js, 20160921_970f1dd445269cda0ba5e6f9fd675983.js, 20160921_a31336f192353e1997fed06b582e1aef.js, 20160921_b32c8921e3390cb8f9450436f4e43cfb.js, 20160921_b8c98d7e4e5c69c2f4fa4fec37a59dfb.js, 20160921_fe8abdad2bc00d1378e2964402e33217.js, 20160922_99c635a67f8963210ce99c7a8cf9cd6c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "61b41be208c77057ce2b56a866ae0e936c6372d0c3a92f126a1cf5090fe0a5e7"
    hash2       = "95544bd07dbc8b2550e3a6bb328d49a808c8749bb3ced90cbb8f5f90782625a1"
    hash3       = "02801a1fe1d3c30ef8c10eab40eabc26c88f8bc28e76e3aecbbb89d0981b21af"
    hash4       = "eb33bb458042e91be0620012d2d05aaafd9742abb0880d1389b5c02b834e9290"
    hash5       = "762774d5263bffcad635355a63715b9cd26c09b53efe134be033e8dff5062b47"
    hash6       = "5ab35ff2eba15a460823fc709e29f7c1041f054096a3690e92c926943d39d6a8"
    hash7       = "f1ea05bc317ec861954db64b30bd293d8ee2f663106d48389d91cfb77247fb1e"
    hash8       = "39d0496129988da40dbbddcff6610a39be1f05ddd7f48a13058b749810c8400d"
    hash9       = "c5b5cdc3be24f457939814321b7f3397a8f4d2370b1e57cdae1f3f10537e562c"

  strings:
    $s1 = ",(function f000(){return \"DYx\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"MJq\";})(),(function f000()" ascii
    $s2 = "n \"Oe\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"MBb\";})(),(fun" ascii
    $s3 = "\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"Mc\";})(),(function f" ascii
    $s4 = "eturn \"Yz\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"Nv\";})()," ascii
    $s5 = "n f000(){return \"TKp\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"T" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}