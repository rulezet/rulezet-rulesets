rule TTP_XOR_QUAD_CurrentVersionRun_c011 {
  strings:
    $key_c011 = { 93 7e [2] b7 70 [2] 9c 5c [2] b2 7e [2] a6 65 [2] a9 7f [2] b7 62 [2] b5 63 [2] ae 65 [2] b2 62 [2] ae 4d }

  condition:
    any of them
}