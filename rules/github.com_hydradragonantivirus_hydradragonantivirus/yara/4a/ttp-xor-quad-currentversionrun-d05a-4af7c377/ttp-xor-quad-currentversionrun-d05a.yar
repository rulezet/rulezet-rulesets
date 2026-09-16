rule TTP_XOR_QUAD_CurrentVersionRun_d05a {
  strings:
    $key_d05a = { 83 35 [2] a7 3b [2] 8c 17 [2] a2 35 [2] b6 2e [2] b9 34 [2] a7 29 [2] a5 28 [2] be 2e [2] a2 29 [2] be 06 }

  condition:
    any of them
}