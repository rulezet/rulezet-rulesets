rule TTP_XOR_QUAD_CurrentVersionRun_fe88 {
  strings:
    $key_fe88 = { ad e7 [2] 89 e9 [2] a2 c5 [2] 8c e7 [2] 98 fc [2] 97 e6 [2] 89 fb [2] 8b fa [2] 90 fc [2] 8c fb [2] 90 d4 }

  condition:
    any of them
}