rule TTP_XOR_MULT_DOSStub_e97a {
  strings:
    $key_e97a = { bd 12 [2] c9 0a [2] 8e 08 [2] c9 19 [2] 87 15 [2] 8b 1f [2] 9c 14 [2] 87 5a [2] ba }

  condition:
    any of them
}