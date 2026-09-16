rule TTP_XOR_QUAD_CurrentVersionRun_c32e {
  strings:
    $key_c32e = { 90 41 [2] b4 4f [2] 9f 63 [2] b1 41 [2] a5 5a [2] aa 40 [2] b4 5d [2] b6 5c [2] ad 5a [2] b1 5d [2] ad 72 }

  condition:
    any of them
}