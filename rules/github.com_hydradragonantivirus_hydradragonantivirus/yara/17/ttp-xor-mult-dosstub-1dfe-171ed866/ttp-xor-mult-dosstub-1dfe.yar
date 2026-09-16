rule TTP_XOR_MULT_DOSStub_1dfe {
  strings:
    $key_1dfe = { 49 96 [2] 3d 8e [2] 7a 8c [2] 3d 9d [2] 73 91 [2] 7f 9b [2] 68 90 [2] 73 de [2] 4e }

  condition:
    any of them
}