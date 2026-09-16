rule TTP_XOR_MULT_DOSStub_9f64 {
  strings:
    $key_9f64 = { cb 0c [2] bf 14 [2] f8 16 [2] bf 07 [2] f1 0b [2] fd 01 [2] ea 0a [2] f1 44 [2] cc }

  condition:
    any of them
}