rule TTP_XOR_QUAD_CurrentVersionRun_cce9 {
  strings:
    $key_cce9 = { 9f 86 [2] bb 88 [2] 90 a4 [2] be 86 [2] aa 9d [2] a5 87 [2] bb 9a [2] b9 9b [2] a2 9d [2] be 9a [2] a2 b5 }

  condition:
    any of them
}