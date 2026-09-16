rule TTP_XOR_QUAD_CurrentVersionRun_c12e {
  strings:
    $key_c12e = { 92 41 [2] b6 4f [2] 9d 63 [2] b3 41 [2] a7 5a [2] a8 40 [2] b6 5d [2] b4 5c [2] af 5a [2] b3 5d [2] af 72 }

  condition:
    any of them
}