rule TTP_XOR_MULT_DOSStub_02ce {
  strings:
    $key_02ce = { 56 a6 [2] 22 be [2] 65 bc [2] 22 ad [2] 6c a1 [2] 60 ab [2] 77 a0 [2] 6c ee [2] 51 }

  condition:
    any of them
}