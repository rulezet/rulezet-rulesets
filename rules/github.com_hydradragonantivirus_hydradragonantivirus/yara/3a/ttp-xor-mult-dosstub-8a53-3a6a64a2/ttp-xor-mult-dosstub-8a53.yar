rule TTP_XOR_MULT_DOSStub_8a53 {
  strings:
    $key_8a53 = { de 3b [2] aa 23 [2] ed 21 [2] aa 30 [2] e4 3c [2] e8 36 [2] ff 3d [2] e4 73 [2] d9 }

  condition:
    any of them
}