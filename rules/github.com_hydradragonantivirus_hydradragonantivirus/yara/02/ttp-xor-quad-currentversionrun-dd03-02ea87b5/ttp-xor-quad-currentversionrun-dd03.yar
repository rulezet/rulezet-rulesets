rule TTP_XOR_QUAD_CurrentVersionRun_dd03 {
  strings:
    $key_dd03 = { 8e 6c [2] aa 62 [2] 81 4e [2] af 6c [2] bb 77 [2] b4 6d [2] aa 70 [2] a8 71 [2] b3 77 [2] af 70 [2] b3 5f }

  condition:
    any of them
}