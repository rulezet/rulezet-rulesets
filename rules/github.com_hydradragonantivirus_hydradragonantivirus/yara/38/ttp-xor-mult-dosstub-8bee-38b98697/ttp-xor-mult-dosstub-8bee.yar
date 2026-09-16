rule TTP_XOR_MULT_DOSStub_8bee {
  strings:
    $key_8bee = { df 86 [2] ab 9e [2] ec 9c [2] ab 8d [2] e5 81 [2] e9 8b [2] fe 80 [2] e5 ce [2] d8 }

  condition:
    any of them
}