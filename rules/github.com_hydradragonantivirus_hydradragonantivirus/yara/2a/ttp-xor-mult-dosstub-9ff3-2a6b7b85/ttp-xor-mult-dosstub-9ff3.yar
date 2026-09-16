rule TTP_XOR_MULT_DOSStub_9ff3 {
  strings:
    $key_9ff3 = { cb 9b [2] bf 83 [2] f8 81 [2] bf 90 [2] f1 9c [2] fd 96 [2] ea 9d [2] f1 d3 [2] cc }

  condition:
    any of them
}