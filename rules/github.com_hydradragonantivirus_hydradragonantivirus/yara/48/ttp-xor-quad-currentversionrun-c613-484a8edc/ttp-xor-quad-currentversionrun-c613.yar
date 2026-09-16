rule TTP_XOR_QUAD_CurrentVersionRun_c613 {
  strings:
    $key_c613 = { 95 7c [2] b1 72 [2] 9a 5e [2] b4 7c [2] a0 67 [2] af 7d [2] b1 60 [2] b3 61 [2] a8 67 [2] b4 60 [2] a8 4f }

  condition:
    any of them
}