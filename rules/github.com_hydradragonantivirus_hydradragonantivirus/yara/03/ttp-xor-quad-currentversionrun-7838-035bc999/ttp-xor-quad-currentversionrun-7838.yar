rule TTP_XOR_QUAD_CurrentVersionRun_7838 {
  strings:
    $key_7838 = { 2b 57 [2] 0f 59 [2] 24 75 [2] 0a 57 [2] 1e 4c [2] 11 56 [2] 0f 4b [2] 0d 4a [2] 16 4c [2] 0a 4b [2] 16 64 }

  condition:
    any of them
}