rule TTP_XOR_MULT_DOSStub_8a1f {
  strings:
    $key_8a1f = { de 77 [2] aa 6f [2] ed 6d [2] aa 7c [2] e4 70 [2] e8 7a [2] ff 71 [2] e4 3f [2] d9 }

  condition:
    any of them
}