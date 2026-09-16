rule TTP_XOR_QUAD_CurrentVersionRun_1944 {
  strings:
    $key_1944 = { 4a 2b [2] 6e 25 [2] 45 09 [2] 6b 2b [2] 7f 30 [2] 70 2a [2] 6e 37 [2] 6c 36 [2] 77 30 [2] 6b 37 [2] 77 18 }

  condition:
    any of them
}