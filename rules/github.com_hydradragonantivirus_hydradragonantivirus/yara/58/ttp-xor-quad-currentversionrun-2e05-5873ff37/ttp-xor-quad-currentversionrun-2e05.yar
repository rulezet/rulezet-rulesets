rule TTP_XOR_QUAD_CurrentVersionRun_2e05 {
  strings:
    $key_2e05 = { 7d 6a [2] 59 64 [2] 72 48 [2] 5c 6a [2] 48 71 [2] 47 6b [2] 59 76 [2] 5b 77 [2] 40 71 [2] 5c 76 [2] 40 59 }

  condition:
    any of them
}