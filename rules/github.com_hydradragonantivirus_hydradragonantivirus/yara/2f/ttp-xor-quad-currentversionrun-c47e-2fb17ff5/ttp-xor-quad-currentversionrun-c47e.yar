rule TTP_XOR_QUAD_CurrentVersionRun_c47e {
  strings:
    $key_c47e = { 97 11 [2] b3 1f [2] 98 33 [2] b6 11 [2] a2 0a [2] ad 10 [2] b3 0d [2] b1 0c [2] aa 0a [2] b6 0d [2] aa 22 }

  condition:
    any of them
}