rule TTP_XOR_MULT_DOSStub_d973 {
  strings:
    $key_d973 = { 8d 1b [2] f9 03 [2] be 01 [2] f9 10 [2] b7 1c [2] bb 16 [2] ac 1d [2] b7 53 [2] 8a }

  condition:
    any of them
}