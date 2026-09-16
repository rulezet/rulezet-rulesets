rule TTP_XOR_MULT_DOSStub_13fe {
  strings:
    $key_13fe = { 47 96 [2] 33 8e [2] 74 8c [2] 33 9d [2] 7d 91 [2] 71 9b [2] 66 90 [2] 7d de [2] 40 }

  condition:
    any of them
}