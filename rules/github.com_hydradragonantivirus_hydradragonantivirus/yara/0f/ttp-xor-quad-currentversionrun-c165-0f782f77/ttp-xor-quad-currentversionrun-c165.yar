rule TTP_XOR_QUAD_CurrentVersionRun_c165 {
  strings:
    $key_c165 = { 92 0a [2] b6 04 [2] 9d 28 [2] b3 0a [2] a7 11 [2] a8 0b [2] b6 16 [2] b4 17 [2] af 11 [2] b3 16 [2] af 39 }

  condition:
    any of them
}