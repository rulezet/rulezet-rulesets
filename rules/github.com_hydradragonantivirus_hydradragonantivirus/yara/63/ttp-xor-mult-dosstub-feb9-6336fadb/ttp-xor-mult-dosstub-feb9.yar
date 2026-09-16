rule TTP_XOR_MULT_DOSStub_feb9 {
  strings:
    $key_feb9 = { aa d1 [2] de c9 [2] 99 cb [2] de da [2] 90 d6 [2] 9c dc [2] 8b d7 [2] 90 99 [2] ad }

  condition:
    any of them
}