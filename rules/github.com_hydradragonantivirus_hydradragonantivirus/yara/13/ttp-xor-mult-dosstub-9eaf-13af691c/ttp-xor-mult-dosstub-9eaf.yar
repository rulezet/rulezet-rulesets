rule TTP_XOR_MULT_DOSStub_9eaf {
  strings:
    $key_9eaf = { ca c7 [2] be df [2] f9 dd [2] be cc [2] f0 c0 [2] fc ca [2] eb c1 [2] f0 8f [2] cd }

  condition:
    any of them
}