rule TTP_XOR_MULT_DOSStub_9ff9 {
  strings:
    $key_9ff9 = { cb 91 [2] bf 89 [2] f8 8b [2] bf 9a [2] f1 96 [2] fd 9c [2] ea 97 [2] f1 d9 [2] cc }

  condition:
    any of them
}