rule TTP_XOR_QUAD_CurrentVersionRun_c456 {
  strings:
    $key_c456 = { 97 39 [2] b3 37 [2] 98 1b [2] b6 39 [2] a2 22 [2] ad 38 [2] b3 25 [2] b1 24 [2] aa 22 [2] b6 25 [2] aa 0a }

  condition:
    any of them
}