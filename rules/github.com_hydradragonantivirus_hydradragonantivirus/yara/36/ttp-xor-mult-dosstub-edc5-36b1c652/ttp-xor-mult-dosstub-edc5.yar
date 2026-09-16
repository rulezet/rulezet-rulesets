rule TTP_XOR_MULT_DOSStub_edc5 {
  strings:
    $key_edc5 = { b9 ad [2] cd b5 [2] 8a b7 [2] cd a6 [2] 83 aa [2] 8f a0 [2] 98 ab [2] 83 e5 [2] be }

  condition:
    any of them
}