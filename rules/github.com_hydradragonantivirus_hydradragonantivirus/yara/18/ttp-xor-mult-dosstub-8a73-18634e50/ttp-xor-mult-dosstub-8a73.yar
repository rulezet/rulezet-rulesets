rule TTP_XOR_MULT_DOSStub_8a73 {
  strings:
    $key_8a73 = { de 1b [2] aa 03 [2] ed 01 [2] aa 10 [2] e4 1c [2] e8 16 [2] ff 1d [2] e4 53 [2] d9 }

  condition:
    any of them
}