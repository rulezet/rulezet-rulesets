rule TTP_XOR_MULT_DOSStub_26a5 {
  strings:
    $key_26a5 = { 72 cd [2] 06 d5 [2] 41 d7 [2] 06 c6 [2] 48 ca [2] 44 c0 [2] 53 cb [2] 48 85 [2] 75 }

  condition:
    any of them
}