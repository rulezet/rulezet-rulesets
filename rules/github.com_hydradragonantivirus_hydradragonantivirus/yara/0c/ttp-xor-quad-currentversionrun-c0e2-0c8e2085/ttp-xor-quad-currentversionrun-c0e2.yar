rule TTP_XOR_QUAD_CurrentVersionRun_c0e2 {
  strings:
    $key_c0e2 = { 93 8d [2] b7 83 [2] 9c af [2] b2 8d [2] a6 96 [2] a9 8c [2] b7 91 [2] b5 90 [2] ae 96 [2] b2 91 [2] ae be }

  condition:
    any of them
}