rule TTP_XOR_MULT_DOSStub_9fea {
  strings:
    $key_9fea = { cb 82 [2] bf 9a [2] f8 98 [2] bf 89 [2] f1 85 [2] fd 8f [2] ea 84 [2] f1 ca [2] cc }

  condition:
    any of them
}