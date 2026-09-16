rule TTP_XOR_MULT_DOSStub_52ed {
  strings:
    $key_52ed = { 06 85 [2] 72 9d [2] 35 9f [2] 72 8e [2] 3c 82 [2] 30 88 [2] 27 83 [2] 3c cd [2] 01 }

  condition:
    any of them
}