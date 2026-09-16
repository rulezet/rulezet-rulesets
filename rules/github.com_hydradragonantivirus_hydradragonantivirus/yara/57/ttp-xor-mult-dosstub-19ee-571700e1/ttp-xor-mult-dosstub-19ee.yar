rule TTP_XOR_MULT_DOSStub_19ee {
  strings:
    $key_19ee = { 4d 86 [2] 39 9e [2] 7e 9c [2] 39 8d [2] 77 81 [2] 7b 8b [2] 6c 80 [2] 77 ce [2] 4a }

  condition:
    any of them
}