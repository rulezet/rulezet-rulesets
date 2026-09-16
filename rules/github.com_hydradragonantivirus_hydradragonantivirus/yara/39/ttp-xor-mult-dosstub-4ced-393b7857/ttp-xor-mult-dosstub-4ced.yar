rule TTP_XOR_MULT_DOSStub_4ced {
  strings:
    $key_4ced = { 18 85 [2] 6c 9d [2] 2b 9f [2] 6c 8e [2] 22 82 [2] 2e 88 [2] 39 83 [2] 22 cd [2] 1f }

  condition:
    any of them
}