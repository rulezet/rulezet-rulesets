rule TTP_XOR_QUAD_CurrentVersionRun_c71e {
  strings:
    $key_c71e = { 94 71 [2] b0 7f [2] 9b 53 [2] b5 71 [2] a1 6a [2] ae 70 [2] b0 6d [2] b2 6c [2] a9 6a [2] b5 6d [2] a9 42 }

  condition:
    any of them
}