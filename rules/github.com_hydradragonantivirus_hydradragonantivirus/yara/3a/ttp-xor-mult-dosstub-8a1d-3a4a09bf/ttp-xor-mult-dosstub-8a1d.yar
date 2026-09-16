rule TTP_XOR_MULT_DOSStub_8a1d {
  strings:
    $key_8a1d = { de 75 [2] aa 6d [2] ed 6f [2] aa 7e [2] e4 72 [2] e8 78 [2] ff 73 [2] e4 3d [2] d9 }

  condition:
    any of them
}