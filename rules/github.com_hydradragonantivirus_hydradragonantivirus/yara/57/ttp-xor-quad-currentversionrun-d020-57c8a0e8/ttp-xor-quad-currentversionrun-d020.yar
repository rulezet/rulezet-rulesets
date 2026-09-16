rule TTP_XOR_QUAD_CurrentVersionRun_d020 {
  strings:
    $key_d020 = { 83 4f [2] a7 41 [2] 8c 6d [2] a2 4f [2] b6 54 [2] b9 4e [2] a7 53 [2] a5 52 [2] be 54 [2] a2 53 [2] be 7c }

  condition:
    any of them
}