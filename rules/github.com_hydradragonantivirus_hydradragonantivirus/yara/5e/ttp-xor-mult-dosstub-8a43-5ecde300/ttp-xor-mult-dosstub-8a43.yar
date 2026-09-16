rule TTP_XOR_MULT_DOSStub_8a43 {
  strings:
    $key_8a43 = { de 2b [2] aa 33 [2] ed 31 [2] aa 20 [2] e4 2c [2] e8 26 [2] ff 2d [2] e4 63 [2] d9 }

  condition:
    any of them
}