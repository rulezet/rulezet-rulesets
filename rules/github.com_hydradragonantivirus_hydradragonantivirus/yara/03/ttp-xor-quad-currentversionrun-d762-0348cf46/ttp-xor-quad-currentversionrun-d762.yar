rule TTP_XOR_QUAD_CurrentVersionRun_d762 {
  strings:
    $key_d762 = { 84 0d [2] a0 03 [2] 8b 2f [2] a5 0d [2] b1 16 [2] be 0c [2] a0 11 [2] a2 10 [2] b9 16 [2] a5 11 [2] b9 3e }

  condition:
    any of them
}