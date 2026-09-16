rule TTP_XOR_QUAD_CurrentVersionRun_c3ba {
  strings:
    $key_c3ba = { 90 d5 [2] b4 db [2] 9f f7 [2] b1 d5 [2] a5 ce [2] aa d4 [2] b4 c9 [2] b6 c8 [2] ad ce [2] b1 c9 [2] ad e6 }

  condition:
    any of them
}