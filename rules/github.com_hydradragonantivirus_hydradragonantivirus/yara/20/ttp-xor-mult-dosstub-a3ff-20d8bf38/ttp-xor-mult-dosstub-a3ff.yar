rule TTP_XOR_MULT_DOSStub_a3ff {
  strings:
    $key_a3ff = { f7 97 [2] 83 8f [2] c4 8d [2] 83 9c [2] cd 90 [2] c1 9a [2] d6 91 [2] cd df [2] f0 }

  condition:
    any of them
}