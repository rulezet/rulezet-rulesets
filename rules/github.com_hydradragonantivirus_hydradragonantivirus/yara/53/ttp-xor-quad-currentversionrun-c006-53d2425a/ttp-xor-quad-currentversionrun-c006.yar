rule TTP_XOR_QUAD_CurrentVersionRun_c006 {
  strings:
    $key_c006 = { 93 69 [2] b7 67 [2] 9c 4b [2] b2 69 [2] a6 72 [2] a9 68 [2] b7 75 [2] b5 74 [2] ae 72 [2] b2 75 [2] ae 5a }

  condition:
    any of them
}