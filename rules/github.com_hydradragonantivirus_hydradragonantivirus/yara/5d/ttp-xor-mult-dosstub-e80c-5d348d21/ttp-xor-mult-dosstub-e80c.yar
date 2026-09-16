rule TTP_XOR_MULT_DOSStub_e80c {
  strings:
    $key_e80c = { bc 64 [2] c8 7c [2] 8f 7e [2] c8 6f [2] 86 63 [2] 8a 69 [2] 9d 62 [2] 86 2c [2] bb }

  condition:
    any of them
}