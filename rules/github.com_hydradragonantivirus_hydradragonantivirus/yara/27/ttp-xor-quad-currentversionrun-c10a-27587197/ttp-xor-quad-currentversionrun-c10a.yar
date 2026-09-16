rule TTP_XOR_QUAD_CurrentVersionRun_c10a {
  strings:
    $key_c10a = { 92 65 [2] b6 6b [2] 9d 47 [2] b3 65 [2] a7 7e [2] a8 64 [2] b6 79 [2] b4 78 [2] af 7e [2] b3 79 [2] af 56 }

  condition:
    any of them
}