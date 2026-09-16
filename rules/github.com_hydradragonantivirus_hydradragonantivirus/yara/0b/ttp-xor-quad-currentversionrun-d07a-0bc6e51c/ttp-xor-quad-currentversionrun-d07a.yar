rule TTP_XOR_QUAD_CurrentVersionRun_d07a {
  strings:
    $key_d07a = { 83 15 [2] a7 1b [2] 8c 37 [2] a2 15 [2] b6 0e [2] b9 14 [2] a7 09 [2] a5 08 [2] be 0e [2] a2 09 [2] be 26 }

  condition:
    any of them
}