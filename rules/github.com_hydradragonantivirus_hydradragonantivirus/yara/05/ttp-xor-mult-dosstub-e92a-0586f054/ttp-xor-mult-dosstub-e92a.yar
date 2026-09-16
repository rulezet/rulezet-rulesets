rule TTP_XOR_MULT_DOSStub_e92a {
  strings:
    $key_e92a = { bd 42 [2] c9 5a [2] 8e 58 [2] c9 49 [2] 87 45 [2] 8b 4f [2] 9c 44 [2] 87 0a [2] ba }

  condition:
    any of them
}