rule TTP_XOR_MULT_DOSStub_c99c {
  strings:
    $key_c99c = { 9d f4 [2] e9 ec [2] ae ee [2] e9 ff [2] a7 f3 [2] ab f9 [2] bc f2 [2] a7 bc [2] 9a }

  condition:
    any of them
}