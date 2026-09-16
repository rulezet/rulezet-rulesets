rule TTP_XOR_MULT_DOSStub_e904 {
  strings:
    $key_e904 = { bd 6c [2] c9 74 [2] 8e 76 [2] c9 67 [2] 87 6b [2] 8b 61 [2] 9c 6a [2] 87 24 [2] ba }

  condition:
    any of them
}