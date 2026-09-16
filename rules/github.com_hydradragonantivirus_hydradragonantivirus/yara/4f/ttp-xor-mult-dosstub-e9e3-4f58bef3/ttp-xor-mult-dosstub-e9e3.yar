rule TTP_XOR_MULT_DOSStub_e9e3 {
  strings:
    $key_e9e3 = { bd 8b [2] c9 93 [2] 8e 91 [2] c9 80 [2] 87 8c [2] 8b 86 [2] 9c 8d [2] 87 c3 [2] ba }

  condition:
    any of them
}