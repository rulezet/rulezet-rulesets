rule TTP_XOR_MULT_DOSStub_6ced {
  strings:
    $key_6ced = { 38 85 [2] 4c 9d [2] 0b 9f [2] 4c 8e [2] 02 82 [2] 0e 88 [2] 19 83 [2] 02 cd [2] 3f }

  condition:
    any of them
}