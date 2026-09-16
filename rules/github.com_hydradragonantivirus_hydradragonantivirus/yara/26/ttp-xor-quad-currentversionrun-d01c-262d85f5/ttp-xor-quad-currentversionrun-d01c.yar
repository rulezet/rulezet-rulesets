rule TTP_XOR_QUAD_CurrentVersionRun_d01c {
  strings:
    $key_d01c = { 83 73 [2] a7 7d [2] 8c 51 [2] a2 73 [2] b6 68 [2] b9 72 [2] a7 6f [2] a5 6e [2] be 68 [2] a2 6f [2] be 40 }

  condition:
    any of them
}