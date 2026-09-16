rule TTP_XOR_MULT_DOSStub_e903 {
  strings:
    $key_e903 = { bd 6b [2] c9 73 [2] 8e 71 [2] c9 60 [2] 87 6c [2] 8b 66 [2] 9c 6d [2] 87 23 [2] ba }

  condition:
    any of them
}