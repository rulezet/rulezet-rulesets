rule TTP_XOR_QUAD_CurrentVersionRun_40f6 {
  strings:
    $key_40f6 = { 13 99 [2] 37 97 [2] 1c bb [2] 32 99 [2] 26 82 [2] 29 98 [2] 37 85 [2] 35 84 [2] 2e 82 [2] 32 85 [2] 2e aa }

  condition:
    any of them
}