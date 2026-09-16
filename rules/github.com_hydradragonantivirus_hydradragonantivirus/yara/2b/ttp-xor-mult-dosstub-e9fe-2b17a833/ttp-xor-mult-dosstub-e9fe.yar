rule TTP_XOR_MULT_DOSStub_e9fe {
  strings:
    $key_e9fe = { bd 96 [2] c9 8e [2] 8e 8c [2] c9 9d [2] 87 91 [2] 8b 9b [2] 9c 90 [2] 87 de [2] ba }

  condition:
    any of them
}