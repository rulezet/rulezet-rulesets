rule TTP_XOR_QUAD_CurrentVersionRun_c13e {
  strings:
    $key_c13e = { 92 51 [2] b6 5f [2] 9d 73 [2] b3 51 [2] a7 4a [2] a8 50 [2] b6 4d [2] b4 4c [2] af 4a [2] b3 4d [2] af 62 }

  condition:
    any of them
}