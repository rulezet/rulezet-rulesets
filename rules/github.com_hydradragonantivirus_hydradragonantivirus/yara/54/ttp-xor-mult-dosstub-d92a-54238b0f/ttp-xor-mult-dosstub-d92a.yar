rule TTP_XOR_MULT_DOSStub_d92a {
  strings:
    $key_d92a = { 8d 42 [2] f9 5a [2] be 58 [2] f9 49 [2] b7 45 [2] bb 4f [2] ac 44 [2] b7 0a [2] 8a }

  condition:
    any of them
}