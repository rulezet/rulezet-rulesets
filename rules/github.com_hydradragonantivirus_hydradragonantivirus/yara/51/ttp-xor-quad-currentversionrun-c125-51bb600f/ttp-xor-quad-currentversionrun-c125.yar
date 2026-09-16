rule TTP_XOR_QUAD_CurrentVersionRun_c125 {
  strings:
    $key_c125 = { 92 4a [2] b6 44 [2] 9d 68 [2] b3 4a [2] a7 51 [2] a8 4b [2] b6 56 [2] b4 57 [2] af 51 [2] b3 56 [2] af 79 }

  condition:
    any of them
}