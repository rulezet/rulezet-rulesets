rule TTP_XOR_MULT_DOSStub_5911 {
  strings:
    $key_5911 = { 0d 79 [2] 79 61 [2] 3e 63 [2] 79 72 [2] 37 7e [2] 3b 74 [2] 2c 7f [2] 37 31 [2] 0a }

  condition:
    any of them
}