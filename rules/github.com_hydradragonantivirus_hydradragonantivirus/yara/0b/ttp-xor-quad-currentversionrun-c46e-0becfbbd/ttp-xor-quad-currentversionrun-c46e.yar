rule TTP_XOR_QUAD_CurrentVersionRun_c46e {
  strings:
    $key_c46e = { 97 01 [2] b3 0f [2] 98 23 [2] b6 01 [2] a2 1a [2] ad 00 [2] b3 1d [2] b1 1c [2] aa 1a [2] b6 1d [2] aa 32 }

  condition:
    any of them
}