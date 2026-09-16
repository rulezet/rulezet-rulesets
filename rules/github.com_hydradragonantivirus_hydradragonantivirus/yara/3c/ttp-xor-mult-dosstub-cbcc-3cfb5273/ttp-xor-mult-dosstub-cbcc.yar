rule TTP_XOR_MULT_DOSStub_cbcc {
  strings:
    $key_cbcc = { 9f a4 [2] eb bc [2] ac be [2] eb af [2] a5 a3 [2] a9 a9 [2] be a2 [2] a5 ec [2] 98 }

  condition:
    any of them
}