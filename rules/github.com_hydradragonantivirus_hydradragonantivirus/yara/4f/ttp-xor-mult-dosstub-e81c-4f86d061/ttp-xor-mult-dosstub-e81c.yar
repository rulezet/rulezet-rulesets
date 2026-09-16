rule TTP_XOR_MULT_DOSStub_e81c {
  strings:
    $key_e81c = { bc 74 [2] c8 6c [2] 8f 6e [2] c8 7f [2] 86 73 [2] 8a 79 [2] 9d 72 [2] 86 3c [2] bb }

  condition:
    any of them
}