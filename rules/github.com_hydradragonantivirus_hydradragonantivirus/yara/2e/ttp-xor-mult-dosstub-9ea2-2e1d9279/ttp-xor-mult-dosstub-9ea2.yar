rule TTP_XOR_MULT_DOSStub_9ea2 {
  strings:
    $key_9ea2 = { ca ca [2] be d2 [2] f9 d0 [2] be c1 [2] f0 cd [2] fc c7 [2] eb cc [2] f0 82 [2] cd }

  condition:
    any of them
}