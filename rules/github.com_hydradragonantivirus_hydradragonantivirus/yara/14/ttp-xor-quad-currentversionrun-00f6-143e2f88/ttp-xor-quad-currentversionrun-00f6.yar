rule TTP_XOR_QUAD_CurrentVersionRun_00f6 {
  strings:
    $key_00f6 = { 53 99 [2] 77 97 [2] 5c bb [2] 72 99 [2] 66 82 [2] 69 98 [2] 77 85 [2] 75 84 [2] 6e 82 [2] 72 85 [2] 6e aa }

  condition:
    any of them
}