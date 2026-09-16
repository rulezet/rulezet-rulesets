rule TTP_XOR_MULT_DOSStub_33fe {
  strings:
    $key_33fe = { 67 96 [2] 13 8e [2] 54 8c [2] 13 9d [2] 5d 91 [2] 51 9b [2] 46 90 [2] 5d de [2] 60 }

  condition:
    any of them
}