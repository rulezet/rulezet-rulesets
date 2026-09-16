rule TTP_XOR_MULT_DOSStub_d90b {
  strings:
    $key_d90b = { 8d 63 [2] f9 7b [2] be 79 [2] f9 68 [2] b7 64 [2] bb 6e [2] ac 65 [2] b7 2b [2] 8a }

  condition:
    any of them
}