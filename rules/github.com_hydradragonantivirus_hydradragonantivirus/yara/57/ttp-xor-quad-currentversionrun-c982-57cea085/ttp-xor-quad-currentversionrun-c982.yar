rule TTP_XOR_QUAD_CurrentVersionRun_c982 {
  strings:
    $key_c982 = { 9a ed [2] be e3 [2] 95 cf [2] bb ed [2] af f6 [2] a0 ec [2] be f1 [2] bc f0 [2] a7 f6 [2] bb f1 [2] a7 de }

  condition:
    any of them
}