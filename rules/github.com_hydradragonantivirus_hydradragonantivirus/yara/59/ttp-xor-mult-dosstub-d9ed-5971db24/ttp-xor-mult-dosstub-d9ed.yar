rule TTP_XOR_MULT_DOSStub_d9ed {
  strings:
    $key_d9ed = { 8d 85 [2] f9 9d [2] be 9f [2] f9 8e [2] b7 82 [2] bb 88 [2] ac 83 [2] b7 cd [2] 8a }

  condition:
    any of them
}