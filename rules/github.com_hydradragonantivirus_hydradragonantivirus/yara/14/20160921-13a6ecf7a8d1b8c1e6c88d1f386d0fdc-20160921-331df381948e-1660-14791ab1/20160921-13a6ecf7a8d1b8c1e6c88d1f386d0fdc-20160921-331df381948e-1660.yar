rule _20160921_13a6ecf7a8d1b8c1e6c88d1f386d0fdc_20160921_331df381948e_1660 {
  meta:
    description = "datamaliciousorder - from files 20160921_13a6ecf7a8d1b8c1e6c88d1f386d0fdc.js, 20160921_331df381948e6d95c6a9496aeda63d16.js, 20160921_63def3fff7f150b1f60fee716b458fd6.js, 20160921_6f40563df6afd13be332d60057d492bb.js, 20160921_71668d4dffd1de11d5c597a2f98e2266.js, 20160921_72cf8bebbcf48b45894fe7d7b3327a58.js, 20160921_83a4b9dfccb435ab7121b53e70b2bb23.js, 20160921_99d82d33214407e421e255b85f02daae.js, 20160921_be882ab89423f06a9e76ba0cb72775fe.js, 20160921_d47b4a8df4397da0f8d93fe0d9eeb14b.js, 20160921_dc989bc33de845eef9826b241e933829.js, 20160921_e08237183b6bb8840bdab8df29dc62ff.js, 20160921_ff1932b6e91481dd80ff6251296b57fe.js, 20160922_99c635a67f8963210ce99c7a8cf9cd6c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a1db38abaeb5bf0ea6f5b5ff0f4a9eedd9ce90cd62e2966ce8936e8e8fbc2905"
    hash2       = "74d3e5ca6efd3e26128cb4a5ab3009003c70f505b353304608d74dfd028df0d7"
    hash3       = "85e2ab59983c4c704998f4c7c577cd8211e7b590b3f200f88616fe64954c10ea"
    hash4       = "f6d3d773ad865f7e3793e6540facc0b8f68d4f503990e93cebc41b933a338a40"
    hash5       = "d9bf036d8b4743496b663218b8ff488676bee9250e9706c1179536db46cbba61"
    hash6       = "004799df77a97e1e1816f6a4a1acf9bec5dfd13ae07613832796a6c9ef0cc578"
    hash7       = "ad277513de073e1dfeba70577234c4da10406e1298f5253b5cf48893971016ed"
    hash8       = "9f95318ee468d352a07628edd848ed3cb97379fab3e416b20eeb631ea656c3a9"
    hash9       = "fe4f2a5579ff9cbd713377a0d5f78bb0c6c30247b6f455ccdb4014a7c298c978"
    hash10      = "78db1c7c22d3adc33c9ba580ac46df953d36c9c15f9c8b211dc68c16595dc18d"
    hash11      = "780c5e07d33732406de5b51436310fbaacb6d3c6fdcb8d9fa40733ae6e903508"
    hash12      = "8d131000a0c435e8674de7020c3a970768f0d66e5b0cf5f711017057a318c00f"
    hash13      = "07e5271d8517f89575dc2737fae5e8da89c7f2f25cd40c68e183d826da6b2bf0"
    hash14      = "c5b5cdc3be24f457939814321b7f3397a8f4d2370b1e57cdae1f3f10537e562c"

  strings:
    $s1  = "n \"GGn\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"YTp\";})(),(fun" ascii
    $s2  = "\"GGn\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"MJq\";})(),(func" ascii
    $s3  = "\"PTs\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"GGn\";})(),(funct" ascii
    $s4  = "rn \"Mt\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(),(fu" ascii
    $s5  = "ction f000(){return \"Br\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"Nx\";})(),(function f000(){return" ascii
    $s6  = "(){return \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";" ascii
    $s7  = "{return \"Nv\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"Kw\";})(" ascii
    $s8  = "})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Br\";})(),(function f000(" ascii
    $s9  = "n f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"R" ascii
    $s10 = "n f000(){return \"KDh\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"" ascii
    $s11 = "ction f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Go\";})(),(function f000(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}