rule TTP_XOR_QUAD_CurrentVersionRun_c7e2 {
  strings:
    $key_c7e2 = { 94 8d [2] b0 83 [2] 9b af [2] b5 8d [2] a1 96 [2] ae 8c [2] b0 91 [2] b2 90 [2] a9 96 [2] b5 91 [2] a9 be }

  condition:
    any of them
}