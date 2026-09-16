rule TTP_XOR_QUAD_CurrentVersionRun_c73f {
  strings:
    $key_c73f = { 94 50 [2] b0 5e [2] 9b 72 [2] b5 50 [2] a1 4b [2] ae 51 [2] b0 4c [2] b2 4d [2] a9 4b [2] b5 4c [2] a9 63 }

  condition:
    any of them
}