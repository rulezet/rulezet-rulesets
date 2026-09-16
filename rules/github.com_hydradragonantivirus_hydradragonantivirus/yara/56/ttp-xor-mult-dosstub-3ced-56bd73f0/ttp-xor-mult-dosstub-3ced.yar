rule TTP_XOR_MULT_DOSStub_3ced {
  strings:
    $key_3ced = { 68 85 [2] 1c 9d [2] 5b 9f [2] 1c 8e [2] 52 82 [2] 5e 88 [2] 49 83 [2] 52 cd [2] 6f }

  condition:
    any of them
}