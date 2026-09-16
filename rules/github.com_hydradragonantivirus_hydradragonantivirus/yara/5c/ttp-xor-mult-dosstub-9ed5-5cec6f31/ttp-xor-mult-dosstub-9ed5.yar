rule TTP_XOR_MULT_DOSStub_9ed5 {
  strings:
    $key_9ed5 = { ca bd [2] be a5 [2] f9 a7 [2] be b6 [2] f0 ba [2] fc b0 [2] eb bb [2] f0 f5 [2] cd }

  condition:
    any of them
}