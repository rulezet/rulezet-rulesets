rule TTP_XOR_QUAD_CurrentVersionRun_cc3a {
  strings:
    $key_cc3a = { 9f 55 [2] bb 5b [2] 90 77 [2] be 55 [2] aa 4e [2] a5 54 [2] bb 49 [2] b9 48 [2] a2 4e [2] be 49 [2] a2 66 }

  condition:
    any of them
}