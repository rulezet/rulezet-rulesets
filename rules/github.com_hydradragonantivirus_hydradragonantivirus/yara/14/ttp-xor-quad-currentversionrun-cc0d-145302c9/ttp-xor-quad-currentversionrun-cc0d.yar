rule TTP_XOR_QUAD_CurrentVersionRun_cc0d {
  strings:
    $key_cc0d = { 9f 62 [2] bb 6c [2] 90 40 [2] be 62 [2] aa 79 [2] a5 63 [2] bb 7e [2] b9 7f [2] a2 79 [2] be 7e [2] a2 51 }

  condition:
    any of them
}