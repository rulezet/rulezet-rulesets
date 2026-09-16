rule TTP_XOR_MULT_DOSStub_e80b {
  strings:
    $key_e80b = { bc 63 [2] c8 7b [2] 8f 79 [2] c8 68 [2] 86 64 [2] 8a 6e [2] 9d 65 [2] 86 2b [2] bb }

  condition:
    any of them
}