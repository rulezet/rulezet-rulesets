rule TTP_XOR_MULT_DOSStub_9eea {
  strings:
    $key_9eea = { ca 82 [2] be 9a [2] f9 98 [2] be 89 [2] f0 85 [2] fc 8f [2] eb 84 [2] f0 ca [2] cd }

  condition:
    any of them
}