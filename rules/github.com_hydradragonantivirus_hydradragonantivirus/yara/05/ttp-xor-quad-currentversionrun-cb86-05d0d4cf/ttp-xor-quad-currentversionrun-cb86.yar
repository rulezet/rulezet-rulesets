rule TTP_XOR_QUAD_CurrentVersionRun_cb86 {
  strings:
    $key_cb86 = { 98 e9 [2] bc e7 [2] 97 cb [2] b9 e9 [2] ad f2 [2] a2 e8 [2] bc f5 [2] be f4 [2] a5 f2 [2] b9 f5 [2] a5 da }

  condition:
    any of them
}