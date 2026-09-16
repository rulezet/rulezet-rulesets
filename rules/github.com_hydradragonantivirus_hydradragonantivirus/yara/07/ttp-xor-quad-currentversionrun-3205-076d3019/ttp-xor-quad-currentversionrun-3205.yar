rule TTP_XOR_QUAD_CurrentVersionRun_3205 {
  strings:
    $key_3205 = { 61 6a [2] 45 64 [2] 6e 48 [2] 40 6a [2] 54 71 [2] 5b 6b [2] 45 76 [2] 47 77 [2] 5c 71 [2] 40 76 [2] 5c 59 }

  condition:
    any of them
}