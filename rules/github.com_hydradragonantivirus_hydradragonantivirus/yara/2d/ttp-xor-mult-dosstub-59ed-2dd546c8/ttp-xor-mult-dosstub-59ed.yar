rule TTP_XOR_MULT_DOSStub_59ed {
  strings:
    $key_59ed = { 0d 85 [2] 79 9d [2] 3e 9f [2] 79 8e [2] 37 82 [2] 3b 88 [2] 2c 83 [2] 37 cd [2] 0a }

  condition:
    any of them
}