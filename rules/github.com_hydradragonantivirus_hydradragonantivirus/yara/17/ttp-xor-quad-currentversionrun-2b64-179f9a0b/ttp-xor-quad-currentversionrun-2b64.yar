rule TTP_XOR_QUAD_CurrentVersionRun_2b64 {
  strings:
    $key_2b64 = { 78 0b [2] 5c 05 [2] 77 29 [2] 59 0b [2] 4d 10 [2] 42 0a [2] 5c 17 [2] 5e 16 [2] 45 10 [2] 59 17 [2] 45 38 }

  condition:
    any of them
}