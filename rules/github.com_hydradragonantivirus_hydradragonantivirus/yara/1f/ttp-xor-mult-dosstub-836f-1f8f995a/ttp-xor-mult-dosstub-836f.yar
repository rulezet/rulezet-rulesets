rule TTP_XOR_MULT_DOSStub_836f {
  strings:
    $key_836f = { d7 07 [2] a3 1f [2] e4 1d [2] a3 0c [2] ed 00 [2] e1 0a [2] f6 01 [2] ed 4f [2] d0 }

  condition:
    any of them
}