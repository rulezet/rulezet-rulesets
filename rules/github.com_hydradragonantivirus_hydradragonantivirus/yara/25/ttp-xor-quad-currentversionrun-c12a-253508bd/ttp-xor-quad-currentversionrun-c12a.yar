rule TTP_XOR_QUAD_CurrentVersionRun_c12a {
  strings:
    $key_c12a = { 92 45 [2] b6 4b [2] 9d 67 [2] b3 45 [2] a7 5e [2] a8 44 [2] b6 59 [2] b4 58 [2] af 5e [2] b3 59 [2] af 76 }

  condition:
    any of them
}