rule TTP_XOR_MULT_DOSStub_8aed {
  strings:
    $key_8aed = { de 85 [2] aa 9d [2] ed 9f [2] aa 8e [2] e4 82 [2] e8 88 [2] ff 83 [2] e4 cd [2] d9 }

  condition:
    any of them
}