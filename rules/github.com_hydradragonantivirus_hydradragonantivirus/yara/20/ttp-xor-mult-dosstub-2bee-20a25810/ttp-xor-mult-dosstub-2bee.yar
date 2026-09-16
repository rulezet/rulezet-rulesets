rule TTP_XOR_MULT_DOSStub_2bee {
  strings:
    $key_2bee = { 7f 86 [2] 0b 9e [2] 4c 9c [2] 0b 8d [2] 45 81 [2] 49 8b [2] 5e 80 [2] 45 ce [2] 78 }

  condition:
    any of them
}