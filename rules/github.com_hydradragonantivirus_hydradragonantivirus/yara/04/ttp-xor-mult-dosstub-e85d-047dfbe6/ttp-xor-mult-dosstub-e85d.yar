rule TTP_XOR_MULT_DOSStub_e85d {
  strings:
    $key_e85d = { bc 35 [2] c8 2d [2] 8f 2f [2] c8 3e [2] 86 32 [2] 8a 38 [2] 9d 33 [2] 86 7d [2] bb }

  condition:
    any of them
}