rule TTP_XOR_MULT_DOSStub_69fe {
  strings:
    $key_69fe = { 3d 96 [2] 49 8e [2] 0e 8c [2] 49 9d [2] 07 91 [2] 0b 9b [2] 1c 90 [2] 07 de [2] 3a }

  condition:
    any of them
}