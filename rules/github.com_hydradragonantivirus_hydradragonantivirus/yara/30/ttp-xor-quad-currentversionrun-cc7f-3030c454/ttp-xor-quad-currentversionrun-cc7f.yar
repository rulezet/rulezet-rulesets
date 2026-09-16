rule TTP_XOR_QUAD_CurrentVersionRun_cc7f {
  strings:
    $key_cc7f = { 9f 10 [2] bb 1e [2] 90 32 [2] be 10 [2] aa 0b [2] a5 11 [2] bb 0c [2] b9 0d [2] a2 0b [2] be 0c [2] a2 23 }

  condition:
    any of them
}