rule TTP_XOR_QUAD_CurrentVersionRun_c74f {
  strings:
    $key_c74f = { 94 20 [2] b0 2e [2] 9b 02 [2] b5 20 [2] a1 3b [2] ae 21 [2] b0 3c [2] b2 3d [2] a9 3b [2] b5 3c [2] a9 13 }

  condition:
    any of them
}