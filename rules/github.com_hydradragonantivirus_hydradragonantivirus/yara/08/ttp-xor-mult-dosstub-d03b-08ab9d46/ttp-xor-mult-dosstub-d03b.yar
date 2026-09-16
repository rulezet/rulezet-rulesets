rule TTP_XOR_MULT_DOSStub_d03b {
  strings:
    $key_d03b = { 84 53 [2] f0 4b [2] b7 49 [2] f0 58 [2] be 54 [2] b2 5e [2] a5 55 [2] be 1b [2] 83 }

  condition:
    any of them
}