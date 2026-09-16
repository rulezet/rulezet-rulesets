rule TTP_XOR_MULT_DOSStub_2ced {
  strings:
    $key_2ced = { 78 85 [2] 0c 9d [2] 4b 9f [2] 0c 8e [2] 42 82 [2] 4e 88 [2] 59 83 [2] 42 cd [2] 7f }

  condition:
    any of them
}