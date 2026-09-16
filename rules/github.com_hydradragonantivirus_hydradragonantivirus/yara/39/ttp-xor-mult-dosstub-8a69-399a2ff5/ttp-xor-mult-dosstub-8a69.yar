rule TTP_XOR_MULT_DOSStub_8a69 {
  strings:
    $key_8a69 = { de 01 [2] aa 19 [2] ed 1b [2] aa 0a [2] e4 06 [2] e8 0c [2] ff 07 [2] e4 49 [2] d9 }

  condition:
    any of them
}