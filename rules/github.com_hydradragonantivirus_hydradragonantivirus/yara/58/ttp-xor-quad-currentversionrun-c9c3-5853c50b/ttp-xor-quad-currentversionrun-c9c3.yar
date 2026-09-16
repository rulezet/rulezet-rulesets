rule TTP_XOR_QUAD_CurrentVersionRun_c9c3 {
  strings:
    $key_c9c3 = { 9a ac [2] be a2 [2] 95 8e [2] bb ac [2] af b7 [2] a0 ad [2] be b0 [2] bc b1 [2] a7 b7 [2] bb b0 [2] a7 9f }

  condition:
    any of them
}