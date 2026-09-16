rule TTP_XOR_QUAD_CurrentVersionRun_c7ff {
  strings:
    $key_c7ff = { 94 90 [2] b0 9e [2] 9b b2 [2] b5 90 [2] a1 8b [2] ae 91 [2] b0 8c [2] b2 8d [2] a9 8b [2] b5 8c [2] a9 a3 }

  condition:
    any of them
}