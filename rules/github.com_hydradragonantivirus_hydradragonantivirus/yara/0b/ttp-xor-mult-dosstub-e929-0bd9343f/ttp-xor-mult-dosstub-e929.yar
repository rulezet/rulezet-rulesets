rule TTP_XOR_MULT_DOSStub_e929 {
  strings:
    $key_e929 = { bd 41 [2] c9 59 [2] 8e 5b [2] c9 4a [2] 87 46 [2] 8b 4c [2] 9c 47 [2] 87 09 [2] ba }

  condition:
    any of them
}