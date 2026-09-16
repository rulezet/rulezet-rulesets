rule TTP_XOR_QUAD_CurrentVersionRun_c76b {
  strings:
    $key_c76b = { 94 04 [2] b0 0a [2] 9b 26 [2] b5 04 [2] a1 1f [2] ae 05 [2] b0 18 [2] b2 19 [2] a9 1f [2] b5 18 [2] a9 37 }

  condition:
    any of them
}