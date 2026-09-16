rule TTP_XOR_QUAD_CurrentVersionRun_d01a {
  strings:
    $key_d01a = { 83 75 [2] a7 7b [2] 8c 57 [2] a2 75 [2] b6 6e [2] b9 74 [2] a7 69 [2] a5 68 [2] be 6e [2] a2 69 [2] be 46 }

  condition:
    any of them
}