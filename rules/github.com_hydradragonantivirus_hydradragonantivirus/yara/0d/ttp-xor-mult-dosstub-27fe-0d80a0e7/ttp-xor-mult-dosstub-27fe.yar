rule TTP_XOR_MULT_DOSStub_27fe {
  strings:
    $key_27fe = { 73 96 [2] 07 8e [2] 40 8c [2] 07 9d [2] 49 91 [2] 45 9b [2] 52 90 [2] 49 de [2] 74 }

  condition:
    any of them
}