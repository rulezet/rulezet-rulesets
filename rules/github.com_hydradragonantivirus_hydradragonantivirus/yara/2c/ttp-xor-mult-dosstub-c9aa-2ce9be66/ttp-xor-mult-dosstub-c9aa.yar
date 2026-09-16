rule TTP_XOR_MULT_DOSStub_c9aa {
  strings:
    $key_c9aa = { 9d c2 [2] e9 da [2] ae d8 [2] e9 c9 [2] a7 c5 [2] ab cf [2] bc c4 [2] a7 8a [2] 9a }

  condition:
    any of them
}