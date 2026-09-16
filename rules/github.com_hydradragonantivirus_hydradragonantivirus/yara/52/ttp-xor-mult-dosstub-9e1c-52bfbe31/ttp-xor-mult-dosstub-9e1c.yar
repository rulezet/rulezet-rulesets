rule TTP_XOR_MULT_DOSStub_9e1c {
  strings:
    $key_9e1c = { ca 74 [2] be 6c [2] f9 6e [2] be 7f [2] f0 73 [2] fc 79 [2] eb 72 [2] f0 3c [2] cd }

  condition:
    any of them
}