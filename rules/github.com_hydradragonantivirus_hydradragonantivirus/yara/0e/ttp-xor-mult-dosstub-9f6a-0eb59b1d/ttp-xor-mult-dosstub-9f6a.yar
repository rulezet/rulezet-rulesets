rule TTP_XOR_MULT_DOSStub_9f6a {
  strings:
    $key_9f6a = { cb 02 [2] bf 1a [2] f8 18 [2] bf 09 [2] f1 05 [2] fd 0f [2] ea 04 [2] f1 4a [2] cc }

  condition:
    any of them
}