rule TTP_XOR_QUAD_CurrentVersionRun_cc0f {
  strings:
    $key_cc0f = { 9f 60 [2] bb 6e [2] 90 42 [2] be 60 [2] aa 7b [2] a5 61 [2] bb 7c [2] b9 7d [2] a2 7b [2] be 7c [2] a2 53 }

  condition:
    any of them
}