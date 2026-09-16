rule TTP_XOR_QUAD_CurrentVersionRun_22f6 {
  strings:
    $key_22f6 = { 71 99 [2] 55 97 [2] 7e bb [2] 50 99 [2] 44 82 [2] 4b 98 [2] 55 85 [2] 57 84 [2] 4c 82 [2] 50 85 [2] 4c aa }

  condition:
    any of them
}