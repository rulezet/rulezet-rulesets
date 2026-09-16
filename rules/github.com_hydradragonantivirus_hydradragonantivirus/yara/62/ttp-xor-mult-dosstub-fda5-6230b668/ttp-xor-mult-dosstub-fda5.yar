rule TTP_XOR_MULT_DOSStub_fda5 {
  strings:
    $key_fda5 = { a9 cd [2] dd d5 [2] 9a d7 [2] dd c6 [2] 93 ca [2] 9f c0 [2] 88 cb [2] 93 85 [2] ae }

  condition:
    any of them
}