rule TTP_XOR_QUAD_CurrentVersionRun_c390 {
  strings:
    $key_c390 = { 90 ff [2] b4 f1 [2] 9f dd [2] b1 ff [2] a5 e4 [2] aa fe [2] b4 e3 [2] b6 e2 [2] ad e4 [2] b1 e3 [2] ad cc }

  condition:
    any of them
}