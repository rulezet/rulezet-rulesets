rule TTP_XOR_MULT_DOSStub_8aea {
  strings:
    $key_8aea = { de 82 [2] aa 9a [2] ed 98 [2] aa 89 [2] e4 85 [2] e8 8f [2] ff 84 [2] e4 ca [2] d9 }

  condition:
    any of them
}