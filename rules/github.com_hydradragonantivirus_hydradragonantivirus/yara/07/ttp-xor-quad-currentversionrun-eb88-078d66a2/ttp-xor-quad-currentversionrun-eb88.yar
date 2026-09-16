rule TTP_XOR_QUAD_CurrentVersionRun_eb88 {
  strings:
    $key_eb88 = { b8 e7 [2] 9c e9 [2] b7 c5 [2] 99 e7 [2] 8d fc [2] 82 e6 [2] 9c fb [2] 9e fa [2] 85 fc [2] 99 fb [2] 85 d4 }

  condition:
    any of them
}