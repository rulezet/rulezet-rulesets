rule TTP_XOR_MULT_DOSStub_22fe {
  strings:
    $key_22fe = { 76 96 [2] 02 8e [2] 45 8c [2] 02 9d [2] 4c 91 [2] 40 9b [2] 57 90 [2] 4c de [2] 71 }

  condition:
    any of them
}