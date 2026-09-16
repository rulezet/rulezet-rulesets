rule TTP_XOR_QUAD_CurrentVersionRun_c113 {
  strings:
    $key_c113 = { 92 7c [2] b6 72 [2] 9d 5e [2] b3 7c [2] a7 67 [2] a8 7d [2] b6 60 [2] b4 61 [2] af 67 [2] b3 60 [2] af 4f }

  condition:
    any of them
}