rule TTP_XOR_QUAD_CurrentVersionRun_d030 {
  strings:
    $key_d030 = { 83 5f [2] a7 51 [2] 8c 7d [2] a2 5f [2] b6 44 [2] b9 5e [2] a7 43 [2] a5 42 [2] be 44 [2] a2 43 [2] be 6c }

  condition:
    any of them
}