rule TTP_XOR_QUAD_CurrentVersionRun_ccef {
  strings:
    $key_ccef = { 9f 80 [2] bb 8e [2] 90 a2 [2] be 80 [2] aa 9b [2] a5 81 [2] bb 9c [2] b9 9d [2] a2 9b [2] be 9c [2] a2 b3 }

  condition:
    any of them
}