rule TTP_XOR_QUAD_CurrentVersionRun_c016 {
  strings:
    $key_c016 = { 93 79 [2] b7 77 [2] 9c 5b [2] b2 79 [2] a6 62 [2] a9 78 [2] b7 65 [2] b5 64 [2] ae 62 [2] b2 65 [2] ae 4a }

  condition:
    any of them
}