rule TTP_XOR_MULT_DOSStub_59ee {
  strings:
    $key_59ee = { 0d 86 [2] 79 9e [2] 3e 9c [2] 79 8d [2] 37 81 [2] 3b 8b [2] 2c 80 [2] 37 ce [2] 0a }

  condition:
    any of them
}