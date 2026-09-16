rule TTP_XOR_MULT_DOSStub_60fe {
  strings:
    $key_60fe = { 34 96 [2] 40 8e [2] 07 8c [2] 40 9d [2] 0e 91 [2] 02 9b [2] 15 90 [2] 0e de [2] 33 }

  condition:
    any of them
}