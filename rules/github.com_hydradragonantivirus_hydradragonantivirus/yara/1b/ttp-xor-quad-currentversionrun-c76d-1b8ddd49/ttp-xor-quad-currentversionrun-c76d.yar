rule TTP_XOR_QUAD_CurrentVersionRun_c76d {
  strings:
    $key_c76d = { 94 02 [2] b0 0c [2] 9b 20 [2] b5 02 [2] a1 19 [2] ae 03 [2] b0 1e [2] b2 1f [2] a9 19 [2] b5 1e [2] a9 31 }

  condition:
    any of them
}