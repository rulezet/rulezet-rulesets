rule TTP_XOR_MULT_DOSStub_62ed {
  strings:
    $key_62ed = { 36 85 [2] 42 9d [2] 05 9f [2] 42 8e [2] 0c 82 [2] 00 88 [2] 17 83 [2] 0c cd [2] 31 }

  condition:
    any of them
}