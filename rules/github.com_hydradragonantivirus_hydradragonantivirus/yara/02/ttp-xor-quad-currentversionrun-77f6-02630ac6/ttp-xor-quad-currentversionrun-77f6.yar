rule TTP_XOR_QUAD_CurrentVersionRun_77f6 {
  strings:
    $key_77f6 = { 24 99 [2] 00 97 [2] 2b bb [2] 05 99 [2] 11 82 [2] 1e 98 [2] 00 85 [2] 02 84 [2] 19 82 [2] 05 85 [2] 19 aa }

  condition:
    any of them
}