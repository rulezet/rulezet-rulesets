rule TTP_XOR_QUAD_CurrentVersionRun_c73d {
  strings:
    $key_c73d = { 94 52 [2] b0 5c [2] 9b 70 [2] b5 52 [2] a1 49 [2] ae 53 [2] b0 4e [2] b2 4f [2] a9 49 [2] b5 4e [2] a9 61 }

  condition:
    any of them
}