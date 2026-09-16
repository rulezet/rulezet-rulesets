rule TTP_XOR_MULT_DOSStub_5bee {
  strings:
    $key_5bee = { 0f 86 [2] 7b 9e [2] 3c 9c [2] 7b 8d [2] 35 81 [2] 39 8b [2] 2e 80 [2] 35 ce [2] 08 }

  condition:
    any of them
}