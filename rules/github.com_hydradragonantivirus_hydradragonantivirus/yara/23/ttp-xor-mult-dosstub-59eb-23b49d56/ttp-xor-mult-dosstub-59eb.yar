rule TTP_XOR_MULT_DOSStub_59eb {
  strings:
    $key_59eb = { 0d 83 [2] 79 9b [2] 3e 99 [2] 79 88 [2] 37 84 [2] 3b 8e [2] 2c 85 [2] 37 cb [2] 0a }

  condition:
    any of them
}