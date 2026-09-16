rule TTP_XOR_QUAD_CurrentVersionRun_56f6 {
  strings:
    $key_56f6 = { 05 99 [2] 21 97 [2] 0a bb [2] 24 99 [2] 30 82 [2] 3f 98 [2] 21 85 [2] 23 84 [2] 38 82 [2] 24 85 [2] 38 aa }

  condition:
    any of them
}