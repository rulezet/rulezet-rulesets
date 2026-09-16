rule TTP_XOR_MULT_DOSStub_0da5 {
  strings:
    $key_0da5 = { 59 cd [2] 2d d5 [2] 6a d7 [2] 2d c6 [2] 63 ca [2] 6f c0 [2] 78 cb [2] 63 85 [2] 5e }

  condition:
    any of them
}