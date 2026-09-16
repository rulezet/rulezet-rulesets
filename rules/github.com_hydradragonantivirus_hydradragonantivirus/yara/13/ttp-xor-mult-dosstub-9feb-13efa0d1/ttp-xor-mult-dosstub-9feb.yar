rule TTP_XOR_MULT_DOSStub_9feb {
  strings:
    $key_9feb = { cb 83 [2] bf 9b [2] f8 99 [2] bf 88 [2] f1 84 [2] fd 8e [2] ea 85 [2] f1 cb [2] cc }

  condition:
    any of them
}