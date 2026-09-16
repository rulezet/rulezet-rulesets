rule TTP_XOR_MULT_DOSStub_0dfe {
  strings:
    $key_0dfe = { 59 96 [2] 2d 8e [2] 6a 8c [2] 2d 9d [2] 63 91 [2] 6f 9b [2] 78 90 [2] 63 de [2] 5e }

  condition:
    any of them
}