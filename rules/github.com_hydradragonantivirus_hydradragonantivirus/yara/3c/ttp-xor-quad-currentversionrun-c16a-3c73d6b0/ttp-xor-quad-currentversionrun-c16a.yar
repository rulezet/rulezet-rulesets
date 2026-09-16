rule TTP_XOR_QUAD_CurrentVersionRun_c16a {
  strings:
    $key_c16a = { 92 05 [2] b6 0b [2] 9d 27 [2] b3 05 [2] a7 1e [2] a8 04 [2] b6 19 [2] b4 18 [2] af 1e [2] b3 19 [2] af 36 }

  condition:
    any of them
}