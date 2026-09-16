rule TTP_XOR_QUAD_CurrentVersionRun_d06a {
  strings:
    $key_d06a = { 83 05 [2] a7 0b [2] 8c 27 [2] a2 05 [2] b6 1e [2] b9 04 [2] a7 19 [2] a5 18 [2] be 1e [2] a2 19 [2] be 36 }

  condition:
    any of them
}