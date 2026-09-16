rule TTP_XOR_QUAD_CurrentVersionRun_c03b {
  strings:
    $key_c03b = { 93 54 [2] b7 5a [2] 9c 76 [2] b2 54 [2] a6 4f [2] a9 55 [2] b7 48 [2] b5 49 [2] ae 4f [2] b2 48 [2] ae 67 }

  condition:
    any of them
}