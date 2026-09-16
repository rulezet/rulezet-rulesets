rule TTP_XOR_MULT_DOSStub_cea8 {
  strings:
    $key_cea8 = { 9a c0 [2] ee d8 [2] a9 da [2] ee cb [2] a0 c7 [2] ac cd [2] bb c6 [2] a0 88 [2] 9d }

  condition:
    any of them
}