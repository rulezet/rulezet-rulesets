rule TTP_XOR_QUAD_CurrentVersionRun_c14a {
  strings:
    $key_c14a = { 92 25 [2] b6 2b [2] 9d 07 [2] b3 25 [2] a7 3e [2] a8 24 [2] b6 39 [2] b4 38 [2] af 3e [2] b3 39 [2] af 16 }

  condition:
    any of them
}