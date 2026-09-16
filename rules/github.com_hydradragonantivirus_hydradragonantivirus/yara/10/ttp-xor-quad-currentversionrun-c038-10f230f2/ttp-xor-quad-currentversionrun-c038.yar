rule TTP_XOR_QUAD_CurrentVersionRun_c038 {
  strings:
    $key_c038 = { 93 57 [2] b7 59 [2] 9c 75 [2] b2 57 [2] a6 4c [2] a9 56 [2] b7 4b [2] b5 4a [2] ae 4c [2] b2 4b [2] ae 64 }

  condition:
    any of them
}