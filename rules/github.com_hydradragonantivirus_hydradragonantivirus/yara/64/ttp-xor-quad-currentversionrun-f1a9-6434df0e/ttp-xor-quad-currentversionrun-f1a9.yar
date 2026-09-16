rule TTP_XOR_QUAD_CurrentVersionRun_f1a9 {
  strings:
    $key_f1a9 = { a2 c6 [2] 86 c8 [2] ad e4 [2] 83 c6 [2] 97 dd [2] 98 c7 [2] 86 da [2] 84 db [2] 9f dd [2] 83 da [2] 9f f5 }

  condition:
    any of them
}