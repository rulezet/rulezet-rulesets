rule TTP_XOR_QUAD_CurrentVersionRun_7807 {
  strings:
    $key_7807 = { 2b 68 [2] 0f 66 [2] 24 4a [2] 0a 68 [2] 1e 73 [2] 11 69 [2] 0f 74 [2] 0d 75 [2] 16 73 [2] 0a 74 [2] 16 5b }

  condition:
    any of them
}