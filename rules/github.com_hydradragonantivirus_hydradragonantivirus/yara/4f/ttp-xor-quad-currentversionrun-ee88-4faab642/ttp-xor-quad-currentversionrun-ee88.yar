rule TTP_XOR_QUAD_CurrentVersionRun_ee88 {
  strings:
    $key_ee88 = { bd e7 [2] 99 e9 [2] b2 c5 [2] 9c e7 [2] 88 fc [2] 87 e6 [2] 99 fb [2] 9b fa [2] 80 fc [2] 9c fb [2] 80 d4 }

  condition:
    any of them
}