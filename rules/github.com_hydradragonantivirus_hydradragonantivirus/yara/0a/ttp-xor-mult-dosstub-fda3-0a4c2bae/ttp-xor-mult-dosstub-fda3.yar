rule TTP_XOR_MULT_DOSStub_fda3 {
  strings:
    $key_fda3 = { a9 cb [2] dd d3 [2] 9a d1 [2] dd c0 [2] 93 cc [2] 9f c6 [2] 88 cd [2] 93 83 [2] ae }

  condition:
    any of them
}