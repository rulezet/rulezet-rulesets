rule TTP_XOR_MULT_DOSStub_e92c {
  strings:
    $key_e92c = { bd 44 [2] c9 5c [2] 8e 5e [2] c9 4f [2] 87 43 [2] 8b 49 [2] 9c 42 [2] 87 0c [2] ba }

  condition:
    any of them
}