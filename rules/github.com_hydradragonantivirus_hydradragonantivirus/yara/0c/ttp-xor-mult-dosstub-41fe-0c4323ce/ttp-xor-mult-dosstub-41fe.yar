rule TTP_XOR_MULT_DOSStub_41fe {
  strings:
    $key_41fe = { 15 96 [2] 61 8e [2] 26 8c [2] 61 9d [2] 2f 91 [2] 23 9b [2] 34 90 [2] 2f de [2] 12 }

  condition:
    any of them
}