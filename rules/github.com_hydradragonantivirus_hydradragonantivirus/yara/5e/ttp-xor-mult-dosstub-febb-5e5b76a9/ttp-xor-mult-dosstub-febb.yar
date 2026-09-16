rule TTP_XOR_MULT_DOSStub_febb {
  strings:
    $key_febb = { aa d3 [2] de cb [2] 99 c9 [2] de d8 [2] 90 d4 [2] 9c de [2] 8b d5 [2] 90 9b [2] ad }

  condition:
    any of them
}