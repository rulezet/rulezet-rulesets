rule TTP_XOR_MULT_DOSStub_dea5 {
  strings:
    $key_dea5 = { 8a cd [2] fe d5 [2] b9 d7 [2] fe c6 [2] b0 ca [2] bc c0 [2] ab cb [2] b0 85 [2] 8d }

  condition:
    any of them
}