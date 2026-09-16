rule TTP_XOR_MULT_DOSStub_8ba7 {
  strings:
    $key_8ba7 = { df cf [2] ab d7 [2] ec d5 [2] ab c4 [2] e5 c8 [2] e9 c2 [2] fe c9 [2] e5 87 [2] d8 }

  condition:
    any of them
}