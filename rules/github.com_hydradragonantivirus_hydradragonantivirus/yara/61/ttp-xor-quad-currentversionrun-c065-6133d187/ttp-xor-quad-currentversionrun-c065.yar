rule TTP_XOR_QUAD_CurrentVersionRun_c065 {
  strings:
    $key_c065 = { 93 0a [2] b7 04 [2] 9c 28 [2] b2 0a [2] a6 11 [2] a9 0b [2] b7 16 [2] b5 17 [2] ae 11 [2] b2 16 [2] ae 39 }

  condition:
    any of them
}