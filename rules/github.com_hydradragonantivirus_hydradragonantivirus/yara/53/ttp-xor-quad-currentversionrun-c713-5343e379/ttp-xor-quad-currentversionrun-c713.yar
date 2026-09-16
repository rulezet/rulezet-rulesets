rule TTP_XOR_QUAD_CurrentVersionRun_c713 {
  strings:
    $key_c713 = { 94 7c [2] b0 72 [2] 9b 5e [2] b5 7c [2] a1 67 [2] ae 7d [2] b0 60 [2] b2 61 [2] a9 67 [2] b5 60 [2] a9 4f }

  condition:
    any of them
}