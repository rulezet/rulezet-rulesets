rule TTP_XOR_MULT_DOSStub_76fe {
  strings:
    $key_76fe = { 22 96 [2] 56 8e [2] 11 8c [2] 56 9d [2] 18 91 [2] 14 9b [2] 03 90 [2] 18 de [2] 25 }

  condition:
    any of them
}