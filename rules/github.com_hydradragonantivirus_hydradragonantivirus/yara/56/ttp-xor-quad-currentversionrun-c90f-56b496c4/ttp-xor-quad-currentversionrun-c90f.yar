rule TTP_XOR_QUAD_CurrentVersionRun_c90f {
  strings:
    $key_c90f = { 9a 60 [2] be 6e [2] 95 42 [2] bb 60 [2] af 7b [2] a0 61 [2] be 7c [2] bc 7d [2] a7 7b [2] bb 7c [2] a7 53 }

  condition:
    any of them
}