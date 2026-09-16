rule TTP_XOR_MULT_DOSStub_8ae8 {
  strings:
    $key_8ae8 = { de 80 [2] aa 98 [2] ed 9a [2] aa 8b [2] e4 87 [2] e8 8d [2] ff 86 [2] e4 c8 [2] d9 }

  condition:
    any of them
}