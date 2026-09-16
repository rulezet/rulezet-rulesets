rule TTP_XOR_MULT_DOSStub_7da5 {
  strings:
    $key_7da5 = { 29 cd [2] 5d d5 [2] 1a d7 [2] 5d c6 [2] 13 ca [2] 1f c0 [2] 08 cb [2] 13 85 [2] 2e }

  condition:
    any of them
}