rule TTP_XOR_MULT_DOSStub_8ba8 {
  strings:
    $key_8ba8 = { df c0 [2] ab d8 [2] ec da [2] ab cb [2] e5 c7 [2] e9 cd [2] fe c6 [2] e5 88 [2] d8 }

  condition:
    any of them
}