rule TTP_XOR_MULT_DOSStub_e84c {
  strings:
    $key_e84c = { bc 24 [2] c8 3c [2] 8f 3e [2] c8 2f [2] 86 23 [2] 8a 29 [2] 9d 22 [2] 86 6c [2] bb }

  condition:
    any of them
}