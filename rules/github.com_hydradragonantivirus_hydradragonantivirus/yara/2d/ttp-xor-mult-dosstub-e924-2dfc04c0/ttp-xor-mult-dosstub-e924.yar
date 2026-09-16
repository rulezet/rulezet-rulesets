rule TTP_XOR_MULT_DOSStub_e924 {
  strings:
    $key_e924 = { bd 4c [2] c9 54 [2] 8e 56 [2] c9 47 [2] 87 4b [2] 8b 41 [2] 9c 4a [2] 87 04 [2] ba }

  condition:
    any of them
}