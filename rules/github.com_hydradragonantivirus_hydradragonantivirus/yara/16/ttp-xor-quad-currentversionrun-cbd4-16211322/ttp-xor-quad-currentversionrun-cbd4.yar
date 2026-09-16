rule TTP_XOR_QUAD_CurrentVersionRun_cbd4 {
  strings:
    $key_cbd4 = { 98 bb [2] bc b5 [2] 97 99 [2] b9 bb [2] ad a0 [2] a2 ba [2] bc a7 [2] be a6 [2] a5 a0 [2] b9 a7 [2] a5 88 }

  condition:
    any of them
}