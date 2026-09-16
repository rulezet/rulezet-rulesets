rule TTP_XOR_QUAD_CurrentVersionRun_c0ce {
  strings:
    $key_c0ce = { 93 a1 [2] b7 af [2] 9c 83 [2] b2 a1 [2] a6 ba [2] a9 a0 [2] b7 bd [2] b5 bc [2] ae ba [2] b2 bd [2] ae 92 }

  condition:
    any of them
}