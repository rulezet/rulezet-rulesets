rule TTP_XOR_QUAD_CurrentVersionRun_fe89 {
  strings:
    $key_fe89 = { ad e6 [2] 89 e8 [2] a2 c4 [2] 8c e6 [2] 98 fd [2] 97 e7 [2] 89 fa [2] 8b fb [2] 90 fd [2] 8c fa [2] 90 d5 }

  condition:
    any of them
}