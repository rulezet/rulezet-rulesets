rule TTP_XOR_QUAD_CurrentVersionRun_cbca {
  strings:
    $key_cbca = { 98 a5 [2] bc ab [2] 97 87 [2] b9 a5 [2] ad be [2] a2 a4 [2] bc b9 [2] be b8 [2] a5 be [2] b9 b9 [2] a5 96 }

  condition:
    any of them
}