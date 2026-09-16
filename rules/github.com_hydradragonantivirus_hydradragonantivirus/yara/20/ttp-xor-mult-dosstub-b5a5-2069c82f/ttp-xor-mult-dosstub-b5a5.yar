rule TTP_XOR_MULT_DOSStub_b5a5 {
  strings:
    $key_b5a5 = { e1 cd [2] 95 d5 [2] d2 d7 [2] 95 c6 [2] db ca [2] d7 c0 [2] c0 cb [2] db 85 [2] e6 }

  condition:
    any of them
}