rule TTP_XOR_MULT_DOSStub_edd8 {
  strings:
    $key_edd8 = { b9 b0 [2] cd a8 [2] 8a aa [2] cd bb [2] 83 b7 [2] 8f bd [2] 98 b6 [2] 83 f8 [2] be }

  condition:
    any of them
}