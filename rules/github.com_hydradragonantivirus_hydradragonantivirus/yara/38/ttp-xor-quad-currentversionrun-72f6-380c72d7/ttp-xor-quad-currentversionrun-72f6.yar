rule TTP_XOR_QUAD_CurrentVersionRun_72f6 {
  strings:
    $key_72f6 = { 21 99 [2] 05 97 [2] 2e bb [2] 00 99 [2] 14 82 [2] 1b 98 [2] 05 85 [2] 07 84 [2] 1c 82 [2] 00 85 [2] 1c aa }

  condition:
    any of them
}