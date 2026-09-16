rule TTP_XOR_MULT_DOSStub_b803 {
  strings:
    $key_b803 = { ec 6b [2] 98 73 [2] df 71 [2] 98 60 [2] d6 6c [2] da 66 [2] cd 6d [2] d6 23 [2] eb }

  condition:
    any of them
}