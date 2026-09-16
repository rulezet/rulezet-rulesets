rule TTP_XOR_QUAD_CurrentVersionRun_d61c {
  strings:
    $key_d61c = { 85 73 [2] a1 7d [2] 8a 51 [2] a4 73 [2] b0 68 [2] bf 72 [2] a1 6f [2] a3 6e [2] b8 68 [2] a4 6f [2] b8 40 }

  condition:
    any of them
}