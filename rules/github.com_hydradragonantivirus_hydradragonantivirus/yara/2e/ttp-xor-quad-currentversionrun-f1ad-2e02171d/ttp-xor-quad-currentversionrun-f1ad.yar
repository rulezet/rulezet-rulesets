rule TTP_XOR_QUAD_CurrentVersionRun_f1ad {
  strings:
    $key_f1ad = { a2 c2 [2] 86 cc [2] ad e0 [2] 83 c2 [2] 97 d9 [2] 98 c3 [2] 86 de [2] 84 df [2] 9f d9 [2] 83 de [2] 9f f1 }

  condition:
    any of them
}