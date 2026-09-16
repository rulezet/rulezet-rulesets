rule TTP_XOR_QUAD_CurrentVersionRun_cc6d {
  strings:
    $key_cc6d = { 9f 02 [2] bb 0c [2] 90 20 [2] be 02 [2] aa 19 [2] a5 03 [2] bb 1e [2] b9 1f [2] a2 19 [2] be 1e [2] a2 31 }

  condition:
    any of them
}