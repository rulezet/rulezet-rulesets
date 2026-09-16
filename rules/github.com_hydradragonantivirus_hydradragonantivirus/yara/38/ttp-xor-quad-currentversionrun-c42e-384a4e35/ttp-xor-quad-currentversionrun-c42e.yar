rule TTP_XOR_QUAD_CurrentVersionRun_c42e {
  strings:
    $key_c42e = { 97 41 [2] b3 4f [2] 98 63 [2] b6 41 [2] a2 5a [2] ad 40 [2] b3 5d [2] b1 5c [2] aa 5a [2] b6 5d [2] aa 72 }

  condition:
    any of them
}