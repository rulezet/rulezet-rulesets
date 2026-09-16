rule TTP_XOR_MULT_DOSStub_28fe {
  strings:
    $key_28fe = { 7c 96 [2] 08 8e [2] 4f 8c [2] 08 9d [2] 46 91 [2] 4a 9b [2] 5d 90 [2] 46 de [2] 7b }

  condition:
    any of them
}