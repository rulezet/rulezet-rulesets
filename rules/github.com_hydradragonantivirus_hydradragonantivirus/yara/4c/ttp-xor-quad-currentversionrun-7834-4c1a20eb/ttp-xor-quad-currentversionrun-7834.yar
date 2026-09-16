rule TTP_XOR_QUAD_CurrentVersionRun_7834 {
  strings:
    $key_7834 = { 2b 5b [2] 0f 55 [2] 24 79 [2] 0a 5b [2] 1e 40 [2] 11 5a [2] 0f 47 [2] 0d 46 [2] 16 40 [2] 0a 47 [2] 16 68 }

  condition:
    any of them
}