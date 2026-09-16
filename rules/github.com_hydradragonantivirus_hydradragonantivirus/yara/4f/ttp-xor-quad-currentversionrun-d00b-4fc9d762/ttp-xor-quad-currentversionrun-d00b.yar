rule TTP_XOR_QUAD_CurrentVersionRun_d00b {
  strings:
    $key_d00b = { 83 64 [2] a7 6a [2] 8c 46 [2] a2 64 [2] b6 7f [2] b9 65 [2] a7 78 [2] a5 79 [2] be 7f [2] a2 78 [2] be 57 }

  condition:
    any of them
}