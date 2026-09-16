rule TTP_XOR_QUAD_CurrentVersionRun_02f6 {
  strings:
    $key_02f6 = { 51 99 [2] 75 97 [2] 5e bb [2] 70 99 [2] 64 82 [2] 6b 98 [2] 75 85 [2] 77 84 [2] 6c 82 [2] 70 85 [2] 6c aa }

  condition:
    any of them
}