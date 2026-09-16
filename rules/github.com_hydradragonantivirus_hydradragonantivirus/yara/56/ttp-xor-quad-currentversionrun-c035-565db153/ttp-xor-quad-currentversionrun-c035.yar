rule TTP_XOR_QUAD_CurrentVersionRun_c035 {
  strings:
    $key_c035 = { 93 5a [2] b7 54 [2] 9c 78 [2] b2 5a [2] a6 41 [2] a9 5b [2] b7 46 [2] b5 47 [2] ae 41 [2] b2 46 [2] ae 69 }

  condition:
    any of them
}