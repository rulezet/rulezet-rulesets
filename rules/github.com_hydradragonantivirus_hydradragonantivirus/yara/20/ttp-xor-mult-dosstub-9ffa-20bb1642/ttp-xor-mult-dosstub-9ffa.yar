rule TTP_XOR_MULT_DOSStub_9ffa {
  strings:
    $key_9ffa = { cb 92 [2] bf 8a [2] f8 88 [2] bf 99 [2] f1 95 [2] fd 9f [2] ea 94 [2] f1 da [2] cc }

  condition:
    any of them
}