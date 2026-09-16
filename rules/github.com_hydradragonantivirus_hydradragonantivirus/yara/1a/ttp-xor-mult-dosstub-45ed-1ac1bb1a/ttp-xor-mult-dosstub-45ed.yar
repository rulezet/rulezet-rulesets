rule TTP_XOR_MULT_DOSStub_45ed {
  strings:
    $key_45ed = { 11 85 [2] 65 9d [2] 22 9f [2] 65 8e [2] 2b 82 [2] 27 88 [2] 30 83 [2] 2b cd [2] 16 }

  condition:
    any of them
}