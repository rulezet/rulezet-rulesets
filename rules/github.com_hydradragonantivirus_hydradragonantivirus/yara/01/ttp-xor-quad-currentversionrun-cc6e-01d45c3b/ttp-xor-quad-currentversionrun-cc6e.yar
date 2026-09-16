rule TTP_XOR_QUAD_CurrentVersionRun_cc6e {
  strings:
    $key_cc6e = { 9f 01 [2] bb 0f [2] 90 23 [2] be 01 [2] aa 1a [2] a5 00 [2] bb 1d [2] b9 1c [2] a2 1a [2] be 1d [2] a2 32 }

  condition:
    any of them
}