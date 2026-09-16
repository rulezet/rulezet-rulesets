rule TTP_XOR_QUAD_CurrentVersionRun_c72c {
  strings:
    $key_c72c = { 94 43 [2] b0 4d [2] 9b 61 [2] b5 43 [2] a1 58 [2] ae 42 [2] b0 5f [2] b2 5e [2] a9 58 [2] b5 5f [2] a9 70 }

  condition:
    any of them
}