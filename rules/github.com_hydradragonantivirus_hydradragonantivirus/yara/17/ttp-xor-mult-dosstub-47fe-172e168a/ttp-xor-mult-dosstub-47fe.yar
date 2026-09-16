rule TTP_XOR_MULT_DOSStub_47fe {
  strings:
    $key_47fe = { 13 96 [2] 67 8e [2] 20 8c [2] 67 9d [2] 29 91 [2] 25 9b [2] 32 90 [2] 29 de [2] 14 }

  condition:
    any of them
}