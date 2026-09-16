rule TTP_XOR_QUAD_CurrentVersionRun_d2ec {
  strings:
    $key_d2ec = { 81 83 [2] a5 8d [2] 8e a1 [2] a0 83 [2] b4 98 [2] bb 82 [2] a5 9f [2] a7 9e [2] bc 98 [2] a0 9f [2] bc b0 }

  condition:
    any of them
}