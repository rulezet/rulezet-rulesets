rule TTP_XOR_MULT_DOSStub_1ced {
  strings:
    $key_1ced = { 48 85 [2] 3c 9d [2] 7b 9f [2] 3c 8e [2] 72 82 [2] 7e 88 [2] 69 83 [2] 72 cd [2] 4f }

  condition:
    any of them
}