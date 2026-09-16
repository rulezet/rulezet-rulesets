rule TTP_XOR_MULT_DOSStub_6da5 {
  strings:
    $key_6da5 = { 39 cd [2] 4d d5 [2] 0a d7 [2] 4d c6 [2] 03 ca [2] 0f c0 [2] 18 cb [2] 03 85 [2] 3e }

  condition:
    any of them
}