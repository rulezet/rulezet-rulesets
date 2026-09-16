rule TTP_XOR_QUAD_CurrentVersionRun_7829 {
  strings:
    $key_7829 = { 2b 46 [2] 0f 48 [2] 24 64 [2] 0a 46 [2] 1e 5d [2] 11 47 [2] 0f 5a [2] 0d 5b [2] 16 5d [2] 0a 5a [2] 16 75 }

  condition:
    any of them
}