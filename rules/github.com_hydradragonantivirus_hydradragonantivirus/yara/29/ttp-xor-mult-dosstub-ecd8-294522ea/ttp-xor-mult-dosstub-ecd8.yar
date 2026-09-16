rule TTP_XOR_MULT_DOSStub_ecd8 {
  strings:
    $key_ecd8 = { b8 b0 [2] cc a8 [2] 8b aa [2] cc bb [2] 82 b7 [2] 8e bd [2] 99 b6 [2] 82 f8 [2] bf }

  condition:
    any of them
}