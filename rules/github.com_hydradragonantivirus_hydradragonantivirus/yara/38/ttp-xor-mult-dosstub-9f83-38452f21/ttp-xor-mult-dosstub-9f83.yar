rule TTP_XOR_MULT_DOSStub_9f83 {
  strings:
    $key_9f83 = { cb eb [2] bf f3 [2] f8 f1 [2] bf e0 [2] f1 ec [2] fd e6 [2] ea ed [2] f1 a3 [2] cc }

  condition:
    any of them
}