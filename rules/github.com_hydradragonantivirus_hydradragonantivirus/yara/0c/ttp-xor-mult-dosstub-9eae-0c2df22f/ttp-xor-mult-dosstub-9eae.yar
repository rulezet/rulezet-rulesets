rule TTP_XOR_MULT_DOSStub_9eae {
  strings:
    $key_9eae = { ca c6 [2] be de [2] f9 dc [2] be cd [2] f0 c1 [2] fc cb [2] eb c0 [2] f0 8e [2] cd }

  condition:
    any of them
}