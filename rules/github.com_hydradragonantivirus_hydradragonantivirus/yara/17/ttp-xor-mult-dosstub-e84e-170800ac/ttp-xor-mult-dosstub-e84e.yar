rule TTP_XOR_MULT_DOSStub_e84e {
  strings:
    $key_e84e = { bc 26 [2] c8 3e [2] 8f 3c [2] c8 2d [2] 86 21 [2] 8a 2b [2] 9d 20 [2] 86 6e [2] bb }

  condition:
    any of them
}