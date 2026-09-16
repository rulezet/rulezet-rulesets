rule TTP_XOR_QUAD_CurrentVersionRun_cbb6 {
  strings:
    $key_cbb6 = { 98 d9 [2] bc d7 [2] 97 fb [2] b9 d9 [2] ad c2 [2] a2 d8 [2] bc c5 [2] be c4 [2] a5 c2 [2] b9 c5 [2] a5 ea }

  condition:
    any of them
}