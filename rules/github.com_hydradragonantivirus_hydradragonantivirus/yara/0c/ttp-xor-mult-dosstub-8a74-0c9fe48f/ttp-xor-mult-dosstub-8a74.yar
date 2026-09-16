rule TTP_XOR_MULT_DOSStub_8a74 {
  strings:
    $key_8a74 = { de 1c [2] aa 04 [2] ed 06 [2] aa 17 [2] e4 1b [2] e8 11 [2] ff 1a [2] e4 54 [2] d9 }

  condition:
    any of them
}