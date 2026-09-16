rule TTP_XOR_QUAD_CurrentVersionRun_c017 {
  strings:
    $key_c017 = { 93 78 [2] b7 76 [2] 9c 5a [2] b2 78 [2] a6 63 [2] a9 79 [2] b7 64 [2] b5 65 [2] ae 63 [2] b2 64 [2] ae 4b }

  condition:
    any of them
}