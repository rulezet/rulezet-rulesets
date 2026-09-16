rule TTP_XOR_MULT_DOSStub_d02b {
  strings:
    $key_d02b = { 84 43 [2] f0 5b [2] b7 59 [2] f0 48 [2] be 44 [2] b2 4e [2] a5 45 [2] be 0b [2] 83 }

  condition:
    any of them
}