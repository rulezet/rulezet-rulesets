rule TTP_XOR_MULT_DOSStub_8a6c {
  strings:
    $key_8a6c = { de 04 [2] aa 1c [2] ed 1e [2] aa 0f [2] e4 03 [2] e8 09 [2] ff 02 [2] e4 4c [2] d9 }

  condition:
    any of them
}