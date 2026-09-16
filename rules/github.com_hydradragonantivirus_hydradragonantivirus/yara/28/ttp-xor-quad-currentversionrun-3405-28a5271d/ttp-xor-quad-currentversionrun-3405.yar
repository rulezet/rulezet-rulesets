rule TTP_XOR_QUAD_CurrentVersionRun_3405 {
  strings:
    $key_3405 = { 67 6a [2] 43 64 [2] 68 48 [2] 46 6a [2] 52 71 [2] 5d 6b [2] 43 76 [2] 41 77 [2] 5a 71 [2] 46 76 [2] 5a 59 }

  condition:
    any of them
}