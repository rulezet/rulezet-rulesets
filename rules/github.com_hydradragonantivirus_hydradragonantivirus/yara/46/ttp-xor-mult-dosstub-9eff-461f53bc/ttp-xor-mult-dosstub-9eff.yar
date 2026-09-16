rule TTP_XOR_MULT_DOSStub_9eff {
  strings:
    $key_9eff = { ca 97 [2] be 8f [2] f9 8d [2] be 9c [2] f0 90 [2] fc 9a [2] eb 91 [2] f0 df [2] cd }

  condition:
    any of them
}