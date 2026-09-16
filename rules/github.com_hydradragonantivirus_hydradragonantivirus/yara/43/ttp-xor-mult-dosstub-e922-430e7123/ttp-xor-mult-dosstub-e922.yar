rule TTP_XOR_MULT_DOSStub_e922 {
  strings:
    $key_e922 = { bd 4a [2] c9 52 [2] 8e 50 [2] c9 41 [2] 87 4d [2] 8b 47 [2] 9c 4c [2] 87 02 [2] ba }

  condition:
    any of them
}