rule TTP_XOR_MULT_DOSStub_9f15 {
  strings:
    $key_9f15 = { cb 7d [2] bf 65 [2] f8 67 [2] bf 76 [2] f1 7a [2] fd 70 [2] ea 7b [2] f1 35 [2] cc }

  condition:
    any of them
}