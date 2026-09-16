rule TTP_XOR_QUAD_CurrentVersionRun_3844 {
  strings:
    $key_3844 = { 6b 2b [2] 4f 25 [2] 64 09 [2] 4a 2b [2] 5e 30 [2] 51 2a [2] 4f 37 [2] 4d 36 [2] 56 30 [2] 4a 37 [2] 56 18 }

  condition:
    any of them
}