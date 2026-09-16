rule TTP_XOR_QUAD_CurrentVersionRun_c762 {
  strings:
    $key_c762 = { 94 0d [2] b0 03 [2] 9b 2f [2] b5 0d [2] a1 16 [2] ae 0c [2] b0 11 [2] b2 10 [2] a9 16 [2] b5 11 [2] a9 3e }

  condition:
    any of them
}