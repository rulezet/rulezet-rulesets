rule TTP_XOR_MULT_DOSStub_d92b {
  strings:
    $key_d92b = { 8d 43 [2] f9 5b [2] be 59 [2] f9 48 [2] b7 44 [2] bb 4e [2] ac 45 [2] b7 0b [2] 8a }

  condition:
    any of them
}