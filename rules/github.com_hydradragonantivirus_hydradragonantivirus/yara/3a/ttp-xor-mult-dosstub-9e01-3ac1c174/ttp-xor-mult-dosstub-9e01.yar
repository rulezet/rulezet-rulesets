rule TTP_XOR_MULT_DOSStub_9e01 {
  strings:
    $key_9e01 = { ca 69 [2] be 71 [2] f9 73 [2] be 62 [2] f0 6e [2] fc 64 [2] eb 6f [2] f0 21 [2] cd }

  condition:
    any of them
}