rule TTP_XOR_QUAD_CurrentVersionRun_c43e {
  strings:
    $key_c43e = { 97 51 [2] b3 5f [2] 98 73 [2] b6 51 [2] a2 4a [2] ad 50 [2] b3 4d [2] b1 4c [2] aa 4a [2] b6 4d [2] aa 62 }

  condition:
    any of them
}