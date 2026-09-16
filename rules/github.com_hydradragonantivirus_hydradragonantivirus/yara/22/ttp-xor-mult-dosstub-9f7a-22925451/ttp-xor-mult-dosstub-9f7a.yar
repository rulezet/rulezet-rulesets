rule TTP_XOR_MULT_DOSStub_9f7a {
  strings:
    $key_9f7a = { cb 12 [2] bf 0a [2] f8 08 [2] bf 19 [2] f1 15 [2] fd 1f [2] ea 14 [2] f1 5a [2] cc }

  condition:
    any of them
}