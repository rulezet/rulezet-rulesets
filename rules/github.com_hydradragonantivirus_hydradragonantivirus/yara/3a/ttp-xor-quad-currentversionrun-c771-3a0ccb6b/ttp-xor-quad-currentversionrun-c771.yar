rule TTP_XOR_QUAD_CurrentVersionRun_c771 {
  strings:
    $key_c771 = { 94 1e [2] b0 10 [2] 9b 3c [2] b5 1e [2] a1 05 [2] ae 1f [2] b0 02 [2] b2 03 [2] a9 05 [2] b5 02 [2] a9 2d }

  condition:
    any of them
}