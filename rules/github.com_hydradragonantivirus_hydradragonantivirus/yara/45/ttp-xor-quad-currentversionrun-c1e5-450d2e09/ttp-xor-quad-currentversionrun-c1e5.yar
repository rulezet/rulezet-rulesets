rule TTP_XOR_QUAD_CurrentVersionRun_c1e5 {
  strings:
    $key_c1e5 = { 92 8a [2] b6 84 [2] 9d a8 [2] b3 8a [2] a7 91 [2] a8 8b [2] b6 96 [2] b4 97 [2] af 91 [2] b3 96 [2] af b9 }

  condition:
    any of them
}