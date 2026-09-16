rule TTP_XOR_QUAD_CurrentVersionRun_f1a8 {
  strings:
    $key_f1a8 = { a2 c7 [2] 86 c9 [2] ad e5 [2] 83 c7 [2] 97 dc [2] 98 c6 [2] 86 db [2] 84 da [2] 9f dc [2] 83 db [2] 9f f4 }

  condition:
    any of them
}