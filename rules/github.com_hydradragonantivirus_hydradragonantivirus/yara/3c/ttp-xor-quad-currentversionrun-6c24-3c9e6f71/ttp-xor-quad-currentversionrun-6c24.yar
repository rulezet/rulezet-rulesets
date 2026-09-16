rule TTP_XOR_QUAD_CurrentVersionRun_6c24 {
  strings:
    $key_6c24 = { 3f 4b [2] 1b 45 [2] 30 69 [2] 1e 4b [2] 0a 50 [2] 05 4a [2] 1b 57 [2] 19 56 [2] 02 50 [2] 1e 57 [2] 02 78 }

  condition:
    any of them
}