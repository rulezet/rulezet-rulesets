rule TTP_XOR_MULT_DOSStub_9f00 {
  strings:
    $key_9f00 = { cb 68 [2] bf 70 [2] f8 72 [2] bf 63 [2] f1 6f [2] fd 65 [2] ea 6e [2] f1 20 [2] cc }

  condition:
    any of them
}