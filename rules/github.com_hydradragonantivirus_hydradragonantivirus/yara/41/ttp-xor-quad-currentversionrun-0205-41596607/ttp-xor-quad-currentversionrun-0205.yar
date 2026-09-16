rule TTP_XOR_QUAD_CurrentVersionRun_0205 {
  strings:
    $key_0205 = { 51 6a [2] 75 64 [2] 5e 48 [2] 70 6a [2] 64 71 [2] 6b 6b [2] 75 76 [2] 77 77 [2] 6c 71 [2] 70 76 [2] 6c 59 }

  condition:
    any of them
}