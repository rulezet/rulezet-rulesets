rule TTP_XOR_MULT_DOSStub_38fe {
  strings:
    $key_38fe = { 6c 96 [2] 18 8e [2] 5f 8c [2] 18 9d [2] 56 91 [2] 5a 9b [2] 4d 90 [2] 56 de [2] 6b }

  condition:
    any of them
}