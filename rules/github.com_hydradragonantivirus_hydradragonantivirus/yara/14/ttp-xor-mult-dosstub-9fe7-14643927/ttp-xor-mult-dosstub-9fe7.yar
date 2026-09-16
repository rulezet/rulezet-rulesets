rule TTP_XOR_MULT_DOSStub_9fe7 {
  strings:
    $key_9fe7 = { cb 8f [2] bf 97 [2] f8 95 [2] bf 84 [2] f1 88 [2] fd 82 [2] ea 89 [2] f1 c7 [2] cc }

  condition:
    any of them
}