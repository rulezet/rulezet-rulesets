rule _20160921_033cb159a63153428b22d38108b692e4_20160921_220036ca1d41_1762 {
  meta:
    description = "datamaliciousorder - from files 20160921_033cb159a63153428b22d38108b692e4.js, 20160921_220036ca1d4152e6bd72a833a4b3f832.js, 20160921_b2c7637ff56cbf278f1a457ae1833df9.js, 20160922_99c635a67f8963210ce99c7a8cf9cd6c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d370303fc83ddc3470e00cb54841641f9f338c2f025096e84d40782778041a8b"
    hash2       = "54f3e02c5b6d4d5d2db9a8d86252256d2f355ce582a09c9d870f84a9047c47ff"
    hash3       = "a19789bb6f28d27bc82c039f4db69fb5cc4c189a7a47cddfffcdc6eace37a408"
    hash4       = "c5b5cdc3be24f457939814321b7f3397a8f4d2370b1e57cdae1f3f10537e562c"

  strings:
    $s1  = "0(){return \"SGs\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"BQb" ascii
    $s2  = "(){return \"Br\";})(),(function f000(){return \"Fs\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Mt\";})" ascii
    $s3  = "),(function f000(){return \"Um\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"TKl\";})(),(function f000(){" ascii
    $s4  = "n f000(){return \"MBb\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"" ascii
    $s5  = "Ml\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"Oe\";})(),(function" ascii
    $s6  = "eturn \"Wy\";})(),(function f000(){return \"Fs\";})(),(function f000(){return \"KIc\";})(),(function f000(){return \"KIc\";})()," ascii
    $s7  = "function f000(){return \"BQb\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"KXg\";})(),(function f000(){re" ascii
    $s8  = "tion f000(){return \"UEg\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Oe\";})(),(function f000(){return " ascii
    $s9  = "})(),(function f000(){return \"DAp\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"DYx\";})(),(function f0" ascii
    $s10 = " \"Qa\";})(),(function f000(){return \"KIc\";})(),(function f000(){return \"KIc\";})(),(function f000(){return \"Tn\";})(),(func" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}