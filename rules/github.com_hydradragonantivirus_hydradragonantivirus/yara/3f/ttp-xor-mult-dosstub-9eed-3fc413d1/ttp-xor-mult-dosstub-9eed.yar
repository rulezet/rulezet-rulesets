rule TTP_XOR_MULT_DOSStub_9eed {
  strings:
    $key_9eed = { ca 85 [2] be 9d [2] f9 9f [2] be 8e [2] f0 82 [2] fc 88 [2] eb 83 [2] f0 cd [2] cd }

  condition:
    any of them
}