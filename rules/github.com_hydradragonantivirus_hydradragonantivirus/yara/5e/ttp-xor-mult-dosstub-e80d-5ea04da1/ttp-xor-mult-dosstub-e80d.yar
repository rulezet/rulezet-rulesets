rule TTP_XOR_MULT_DOSStub_e80d {
  strings:
    $key_e80d = { bc 65 [2] c8 7d [2] 8f 7f [2] c8 6e [2] 86 62 [2] 8a 68 [2] 9d 63 [2] 86 2d [2] bb }

  condition:
    any of them
}