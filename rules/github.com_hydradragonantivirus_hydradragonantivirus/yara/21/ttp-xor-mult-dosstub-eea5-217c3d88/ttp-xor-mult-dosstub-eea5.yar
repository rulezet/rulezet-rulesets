rule TTP_XOR_MULT_DOSStub_eea5 {
  strings:
    $key_eea5 = { ba cd [2] ce d5 [2] 89 d7 [2] ce c6 [2] 80 ca [2] 8c c0 [2] 9b cb [2] 80 85 [2] bd }

  condition:
    any of them
}