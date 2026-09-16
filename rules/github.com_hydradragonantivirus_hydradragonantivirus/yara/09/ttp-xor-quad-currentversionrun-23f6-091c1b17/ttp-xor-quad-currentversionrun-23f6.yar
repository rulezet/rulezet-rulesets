rule TTP_XOR_QUAD_CurrentVersionRun_23f6 {
  strings:
    $key_23f6 = { 70 99 [2] 54 97 [2] 7f bb [2] 51 99 [2] 45 82 [2] 4a 98 [2] 54 85 [2] 56 84 [2] 4d 82 [2] 51 85 [2] 4d aa }

  condition:
    any of them
}