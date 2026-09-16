rule TTP_XOR_QUAD_CurrentVersionRun_c138 {
  strings:
    $key_c138 = { 92 57 [2] b6 59 [2] 9d 75 [2] b3 57 [2] a7 4c [2] a8 56 [2] b6 4b [2] b4 4a [2] af 4c [2] b3 4b [2] af 64 }

  condition:
    any of them
}