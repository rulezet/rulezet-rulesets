rule TTP_XOR_QUAD_CurrentVersionRun_20f6 {
  strings:
    $key_20f6 = { 73 99 [2] 57 97 [2] 7c bb [2] 52 99 [2] 46 82 [2] 49 98 [2] 57 85 [2] 55 84 [2] 4e 82 [2] 52 85 [2] 4e aa }

  condition:
    any of them
}