rule TTP_XOR_MULT_DOSStub_8ae2 {
  strings:
    $key_8ae2 = { de 8a [2] aa 92 [2] ed 90 [2] aa 81 [2] e4 8d [2] e8 87 [2] ff 8c [2] e4 c2 [2] d9 }

  condition:
    any of them
}