rule TTP_XOR_MULT_DOSStub_3da5 {
  strings:
    $key_3da5 = { 69 cd [2] 1d d5 [2] 5a d7 [2] 1d c6 [2] 53 ca [2] 5f c0 [2] 48 cb [2] 53 85 [2] 6e }

  condition:
    any of them
}