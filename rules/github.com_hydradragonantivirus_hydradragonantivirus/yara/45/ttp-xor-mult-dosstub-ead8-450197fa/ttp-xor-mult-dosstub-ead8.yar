rule TTP_XOR_MULT_DOSStub_ead8 {
  strings:
    $key_ead8 = { be b0 [2] ca a8 [2] 8d aa [2] ca bb [2] 84 b7 [2] 88 bd [2] 9f b6 [2] 84 f8 [2] b9 }

  condition:
    any of them
}