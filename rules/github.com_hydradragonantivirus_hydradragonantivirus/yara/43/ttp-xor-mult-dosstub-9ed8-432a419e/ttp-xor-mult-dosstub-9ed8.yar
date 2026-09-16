rule TTP_XOR_MULT_DOSStub_9ed8 {
  strings:
    $key_9ed8 = { ca b0 [2] be a8 [2] f9 aa [2] be bb [2] f0 b7 [2] fc bd [2] eb b6 [2] f0 f8 [2] cd }

  condition:
    any of them
}