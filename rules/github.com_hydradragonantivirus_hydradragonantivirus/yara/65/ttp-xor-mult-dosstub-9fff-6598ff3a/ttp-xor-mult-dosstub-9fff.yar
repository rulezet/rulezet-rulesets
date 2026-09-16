rule TTP_XOR_MULT_DOSStub_9fff {
  strings:
    $key_9fff = { cb 97 [2] bf 8f [2] f8 8d [2] bf 9c [2] f1 90 [2] fd 9a [2] ea 91 [2] f1 df [2] cc }

  condition:
    any of them
}