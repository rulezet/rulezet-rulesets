rule TTP_XOR_MULT_DOSStub_e84b {
  strings:
    $key_e84b = { bc 23 [2] c8 3b [2] 8f 39 [2] c8 28 [2] 86 24 [2] 8a 2e [2] 9d 25 [2] 86 6b [2] bb }

  condition:
    any of them
}