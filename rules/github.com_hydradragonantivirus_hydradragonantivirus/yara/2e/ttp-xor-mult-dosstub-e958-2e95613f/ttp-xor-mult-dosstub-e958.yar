rule TTP_XOR_MULT_DOSStub_e958 {
  strings:
    $key_e958 = { bd 30 [2] c9 28 [2] 8e 2a [2] c9 3b [2] 87 37 [2] 8b 3d [2] 9c 36 [2] 87 78 [2] ba }

  condition:
    any of them
}