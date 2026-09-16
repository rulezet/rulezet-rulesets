rule TTP_XOR_MULT_DOSStub_9ea9 {
  strings:
    $key_9ea9 = { ca c1 [2] be d9 [2] f9 db [2] be ca [2] f0 c6 [2] fc cc [2] eb c7 [2] f0 89 [2] cd }

  condition:
    any of them
}