rule TTP_XOR_QUAD_CurrentVersionRun_d2e0 {
  strings:
    $key_d2e0 = { 81 8f [2] a5 81 [2] 8e ad [2] a0 8f [2] b4 94 [2] bb 8e [2] a5 93 [2] a7 92 [2] bc 94 [2] a0 93 [2] bc bc }

  condition:
    any of them
}