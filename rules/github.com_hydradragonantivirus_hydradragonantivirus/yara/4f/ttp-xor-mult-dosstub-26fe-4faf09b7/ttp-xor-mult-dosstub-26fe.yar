rule TTP_XOR_MULT_DOSStub_26fe {
  strings:
    $key_26fe = { 72 96 [2] 06 8e [2] 41 8c [2] 06 9d [2] 48 91 [2] 44 9b [2] 53 90 [2] 48 de [2] 75 }

  condition:
    any of them
}