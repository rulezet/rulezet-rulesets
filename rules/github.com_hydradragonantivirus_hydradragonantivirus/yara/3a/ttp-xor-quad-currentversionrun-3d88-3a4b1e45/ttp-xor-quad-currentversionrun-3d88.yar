rule TTP_XOR_QUAD_CurrentVersionRun_3d88 {
  strings:
    $key_3d88 = { 6e e7 [2] 4a e9 [2] 61 c5 [2] 4f e7 [2] 5b fc [2] 54 e6 [2] 4a fb [2] 48 fa [2] 53 fc [2] 4f fb [2] 53 d4 }

  condition:
    any of them
}