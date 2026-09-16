rule TTP_XOR_QUAD_CurrentVersionRun_c72f {
  strings:
    $key_c72f = { 94 40 [2] b0 4e [2] 9b 62 [2] b5 40 [2] a1 5b [2] ae 41 [2] b0 5c [2] b2 5d [2] a9 5b [2] b5 5c [2] a9 73 }

  condition:
    any of them
}