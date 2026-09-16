rule TTP_XOR_MULT_DOSStub_03fe {
  strings:
    $key_03fe = { 57 96 [2] 23 8e [2] 64 8c [2] 23 9d [2] 6d 91 [2] 61 9b [2] 76 90 [2] 6d de [2] 50 }

  condition:
    any of them
}