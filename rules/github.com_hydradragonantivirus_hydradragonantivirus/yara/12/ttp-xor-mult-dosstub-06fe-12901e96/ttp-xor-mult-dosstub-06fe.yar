rule TTP_XOR_MULT_DOSStub_06fe {
  strings:
    $key_06fe = { 52 96 [2] 26 8e [2] 61 8c [2] 26 9d [2] 68 91 [2] 64 9b [2] 73 90 [2] 68 de [2] 55 }

  condition:
    any of them
}