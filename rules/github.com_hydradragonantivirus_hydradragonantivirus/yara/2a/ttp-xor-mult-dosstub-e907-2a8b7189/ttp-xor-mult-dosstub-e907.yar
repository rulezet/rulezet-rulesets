rule TTP_XOR_MULT_DOSStub_e907 {
  strings:
    $key_e907 = { bd 6f [2] c9 77 [2] 8e 75 [2] c9 64 [2] 87 68 [2] 8b 62 [2] 9c 69 [2] 87 27 [2] ba }

  condition:
    any of them
}