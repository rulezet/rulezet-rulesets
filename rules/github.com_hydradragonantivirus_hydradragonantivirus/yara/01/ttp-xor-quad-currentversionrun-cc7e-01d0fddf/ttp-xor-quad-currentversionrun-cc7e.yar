rule TTP_XOR_QUAD_CurrentVersionRun_cc7e {
  strings:
    $key_cc7e = { 9f 11 [2] bb 1f [2] 90 33 [2] be 11 [2] aa 0a [2] a5 10 [2] bb 0d [2] b9 0c [2] a2 0a [2] be 0d [2] a2 22 }

  condition:
    any of them
}