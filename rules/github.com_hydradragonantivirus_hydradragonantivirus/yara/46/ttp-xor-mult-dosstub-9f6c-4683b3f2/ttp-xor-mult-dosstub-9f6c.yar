rule TTP_XOR_MULT_DOSStub_9f6c {
  strings:
    $key_9f6c = { cb 04 [2] bf 1c [2] f8 1e [2] bf 0f [2] f1 03 [2] fd 09 [2] ea 02 [2] f1 4c [2] cc }

  condition:
    any of them
}