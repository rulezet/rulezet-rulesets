rule TTP_XOR_QUAD_CurrentVersionRun_62f6 {
  strings:
    $key_62f6 = { 31 99 [2] 15 97 [2] 3e bb [2] 10 99 [2] 04 82 [2] 0b 98 [2] 15 85 [2] 17 84 [2] 0c 82 [2] 10 85 [2] 0c aa }

  condition:
    any of them
}