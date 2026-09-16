rule TTP_XOR_MULT_DOSStub_32fe {
  strings:
    $key_32fe = { 66 96 [2] 12 8e [2] 55 8c [2] 12 9d [2] 5c 91 [2] 50 9b [2] 47 90 [2] 5c de [2] 61 }

  condition:
    any of them
}