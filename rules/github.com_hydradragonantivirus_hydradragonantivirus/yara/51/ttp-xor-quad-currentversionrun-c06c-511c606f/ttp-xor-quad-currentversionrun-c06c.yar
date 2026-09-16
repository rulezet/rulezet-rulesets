rule TTP_XOR_QUAD_CurrentVersionRun_c06c {
  strings:
    $key_c06c = { 93 03 [2] b7 0d [2] 9c 21 [2] b2 03 [2] a6 18 [2] a9 02 [2] b7 1f [2] b5 1e [2] ae 18 [2] b2 1f [2] ae 30 }

  condition:
    any of them
}