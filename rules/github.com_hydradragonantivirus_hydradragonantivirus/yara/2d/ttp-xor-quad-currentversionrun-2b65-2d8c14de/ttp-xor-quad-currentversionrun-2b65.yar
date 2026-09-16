rule TTP_XOR_QUAD_CurrentVersionRun_2b65 {
  strings:
    $key_2b65 = { 78 0a [2] 5c 04 [2] 77 28 [2] 59 0a [2] 4d 11 [2] 42 0b [2] 5c 16 [2] 5e 17 [2] 45 11 [2] 59 16 [2] 45 39 }

  condition:
    any of them
}