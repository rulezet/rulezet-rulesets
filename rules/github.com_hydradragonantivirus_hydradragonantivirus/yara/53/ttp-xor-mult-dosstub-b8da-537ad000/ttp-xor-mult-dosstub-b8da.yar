rule TTP_XOR_MULT_DOSStub_b8da {
  strings:
    $key_b8da = { ec b2 [2] 98 aa [2] df a8 [2] 98 b9 [2] d6 b5 [2] da bf [2] cd b4 [2] d6 fa [2] eb }

  condition:
    any of them
}