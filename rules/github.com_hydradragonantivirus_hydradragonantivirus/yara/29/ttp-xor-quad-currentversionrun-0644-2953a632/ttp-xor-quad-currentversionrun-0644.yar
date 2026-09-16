rule TTP_XOR_QUAD_CurrentVersionRun_0644 {
  strings:
    $key_0644 = { 55 2b [2] 71 25 [2] 5a 09 [2] 74 2b [2] 60 30 [2] 6f 2a [2] 71 37 [2] 73 36 [2] 68 30 [2] 74 37 [2] 68 18 }

  condition:
    any of them
}