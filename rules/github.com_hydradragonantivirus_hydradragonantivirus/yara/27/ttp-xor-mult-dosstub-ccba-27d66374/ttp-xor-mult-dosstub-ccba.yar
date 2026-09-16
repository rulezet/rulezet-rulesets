rule TTP_XOR_MULT_DOSStub_ccba {
  strings:
    $key_ccba = { 98 d2 [2] ec ca [2] ab c8 [2] ec d9 [2] a2 d5 [2] ae df [2] b9 d4 [2] a2 9a [2] 9f }

  condition:
    any of them
}