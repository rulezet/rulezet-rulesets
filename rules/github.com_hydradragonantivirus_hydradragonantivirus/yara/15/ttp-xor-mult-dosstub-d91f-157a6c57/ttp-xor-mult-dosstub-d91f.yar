rule TTP_XOR_MULT_DOSStub_d91f {
  strings:
    $key_d91f = { 8d 77 [2] f9 6f [2] be 6d [2] f9 7c [2] b7 70 [2] bb 7a [2] ac 71 [2] b7 3f [2] 8a }

  condition:
    any of them
}