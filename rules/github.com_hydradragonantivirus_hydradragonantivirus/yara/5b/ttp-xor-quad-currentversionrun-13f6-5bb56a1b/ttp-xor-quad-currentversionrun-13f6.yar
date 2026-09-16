rule TTP_XOR_QUAD_CurrentVersionRun_13f6 {
  strings:
    $key_13f6 = { 40 99 [2] 64 97 [2] 4f bb [2] 61 99 [2] 75 82 [2] 7a 98 [2] 64 85 [2] 66 84 [2] 7d 82 [2] 61 85 [2] 7d aa }

  condition:
    any of them
}