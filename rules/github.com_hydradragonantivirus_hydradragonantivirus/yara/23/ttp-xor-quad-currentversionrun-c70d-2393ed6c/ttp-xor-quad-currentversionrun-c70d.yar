rule TTP_XOR_QUAD_CurrentVersionRun_c70d {
  strings:
    $key_c70d = { 94 62 [2] b0 6c [2] 9b 40 [2] b5 62 [2] a1 79 [2] ae 63 [2] b0 7e [2] b2 7f [2] a9 79 [2] b5 7e [2] a9 51 }

  condition:
    any of them
}