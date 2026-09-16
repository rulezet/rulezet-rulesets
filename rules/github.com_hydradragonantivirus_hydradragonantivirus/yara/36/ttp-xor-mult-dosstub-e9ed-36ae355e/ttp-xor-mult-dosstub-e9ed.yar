rule TTP_XOR_MULT_DOSStub_e9ed {
  strings:
    $key_e9ed = { bd 85 [2] c9 9d [2] 8e 9f [2] c9 8e [2] 87 82 [2] 8b 88 [2] 9c 83 [2] 87 cd [2] ba }

  condition:
    any of them
}