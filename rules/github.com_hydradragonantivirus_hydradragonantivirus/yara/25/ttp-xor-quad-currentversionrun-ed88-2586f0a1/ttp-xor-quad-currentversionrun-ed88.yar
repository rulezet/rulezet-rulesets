rule TTP_XOR_QUAD_CurrentVersionRun_ed88 {
  strings:
    $key_ed88 = { be e7 [2] 9a e9 [2] b1 c5 [2] 9f e7 [2] 8b fc [2] 84 e6 [2] 9a fb [2] 98 fa [2] 83 fc [2] 9f fb [2] 83 d4 }

  condition:
    any of them
}