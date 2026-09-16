rule TTP_XOR_MULT_DOSStub_8ba5 {
  strings:
    $key_8ba5 = { df cd [2] ab d5 [2] ec d7 [2] ab c6 [2] e5 ca [2] e9 c0 [2] fe cb [2] e5 85 [2] d8 }

  condition:
    any of them
}