rule TTP_XOR_QUAD_CurrentVersionRun_c476 {
  strings:
    $key_c476 = { 97 19 [2] b3 17 [2] 98 3b [2] b6 19 [2] a2 02 [2] ad 18 [2] b3 05 [2] b1 04 [2] aa 02 [2] b6 05 [2] aa 2a }

  condition:
    any of them
}