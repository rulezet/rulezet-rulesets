rule TTP_XOR_MULT_DOSStub_8a10 {
  strings:
    $key_8a10 = { de 78 [2] aa 60 [2] ed 62 [2] aa 73 [2] e4 7f [2] e8 75 [2] ff 7e [2] e4 30 [2] d9 }

  condition:
    any of them
}