rule TTP_XOR_MULT_DOSStub_7feb {
  strings:
    $key_7feb = { 2b 83 [2] 5f 9b [2] 18 99 [2] 5f 88 [2] 11 84 [2] 1d 8e [2] 0a 85 [2] 11 cb [2] 2c }

  condition:
    any of them
}