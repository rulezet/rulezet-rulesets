rule TTP_XOR_QUAD_CurrentVersionRun_c37e {
  strings:
    $key_c37e = { 90 11 [2] b4 1f [2] 9f 33 [2] b1 11 [2] a5 0a [2] aa 10 [2] b4 0d [2] b6 0c [2] ad 0a [2] b1 0d [2] ad 22 }

  condition:
    any of them
}