rule TTP_XOR_MULT_DOSStub_8ae3 {
  strings:
    $key_8ae3 = { de 8b [2] aa 93 [2] ed 91 [2] aa 80 [2] e4 8c [2] e8 86 [2] ff 8d [2] e4 c3 [2] d9 }

  condition:
    any of them
}