rule TTP_XOR_MULT_DOSStub_edf5 {
  strings:
    $key_edf5 = { b9 9d [2] cd 85 [2] 8a 87 [2] cd 96 [2] 83 9a [2] 8f 90 [2] 98 9b [2] 83 d5 [2] be }

  condition:
    any of them
}