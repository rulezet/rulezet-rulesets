rule TTP_XOR_MULT_DOSStub_bfb2 {
  strings:
    $key_bfb2 = { eb da [2] 9f c2 [2] d8 c0 [2] 9f d1 [2] d1 dd [2] dd d7 [2] ca dc [2] d1 92 [2] ec }

  condition:
    any of them
}