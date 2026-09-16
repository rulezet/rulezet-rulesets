rule TTP_XOR_MULT_DOSStub_8a6b {
  strings:
    $key_8a6b = { de 03 [2] aa 1b [2] ed 19 [2] aa 08 [2] e4 04 [2] e8 0e [2] ff 05 [2] e4 4b [2] d9 }

  condition:
    any of them
}