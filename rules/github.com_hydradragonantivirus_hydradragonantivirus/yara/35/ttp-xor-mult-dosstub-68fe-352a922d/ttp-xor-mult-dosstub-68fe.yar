rule TTP_XOR_MULT_DOSStub_68fe {
  strings:
    $key_68fe = { 3c 96 [2] 48 8e [2] 0f 8c [2] 48 9d [2] 06 91 [2] 0a 9b [2] 1d 90 [2] 06 de [2] 3b }

  condition:
    any of them
}