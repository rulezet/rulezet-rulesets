rule TTP_XOR_MULT_DOSStub_c2ce {
  strings:
    $key_c2ce = { 96 a6 [2] e2 be [2] a5 bc [2] e2 ad [2] ac a1 [2] a0 ab [2] b7 a0 [2] ac ee [2] 91 }

  condition:
    any of them
}