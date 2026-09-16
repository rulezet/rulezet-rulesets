rule TTP_XOR_MULT_DOSStub_e801 {
  strings:
    $key_e801 = { bc 69 [2] c8 71 [2] 8f 73 [2] c8 62 [2] 86 6e [2] 8a 64 [2] 9d 6f [2] 86 21 [2] bb }

  condition:
    any of them
}