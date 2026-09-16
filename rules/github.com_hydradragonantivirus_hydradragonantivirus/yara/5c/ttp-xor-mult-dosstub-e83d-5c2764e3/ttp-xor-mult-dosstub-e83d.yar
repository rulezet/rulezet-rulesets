rule TTP_XOR_MULT_DOSStub_e83d {
  strings:
    $key_e83d = { bc 55 [2] c8 4d [2] 8f 4f [2] c8 5e [2] 86 52 [2] 8a 58 [2] 9d 53 [2] 86 1d [2] bb }

  condition:
    any of them
}