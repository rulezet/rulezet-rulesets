rule TTP_XOR_QUAD_CurrentVersionRun_d07c {
  strings:
    $key_d07c = { 83 13 [2] a7 1d [2] 8c 31 [2] a2 13 [2] b6 08 [2] b9 12 [2] a7 0f [2] a5 0e [2] be 08 [2] a2 0f [2] be 20 }

  condition:
    any of them
}