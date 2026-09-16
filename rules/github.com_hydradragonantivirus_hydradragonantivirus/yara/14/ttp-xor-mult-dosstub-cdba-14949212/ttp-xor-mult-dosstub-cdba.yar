rule TTP_XOR_MULT_DOSStub_cdba {
  strings:
    $key_cdba = { 99 d2 [2] ed ca [2] aa c8 [2] ed d9 [2] a3 d5 [2] af df [2] b8 d4 [2] a3 9a [2] 9e }

  condition:
    any of them
}