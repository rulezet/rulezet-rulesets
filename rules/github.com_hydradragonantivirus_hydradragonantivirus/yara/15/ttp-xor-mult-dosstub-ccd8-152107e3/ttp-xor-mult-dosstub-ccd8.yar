rule TTP_XOR_MULT_DOSStub_ccd8 {
  strings:
    $key_ccd8 = { 98 b0 [2] ec a8 [2] ab aa [2] ec bb [2] a2 b7 [2] ae bd [2] b9 b6 [2] a2 f8 [2] 9f }

  condition:
    any of them
}