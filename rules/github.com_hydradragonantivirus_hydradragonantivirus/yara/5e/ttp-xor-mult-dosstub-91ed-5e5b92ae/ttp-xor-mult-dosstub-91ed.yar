rule TTP_XOR_MULT_DOSStub_91ed {
  strings:
    $key_91ed = { c5 85 [2] b1 9d [2] f6 9f [2] b1 8e [2] ff 82 [2] f3 88 [2] e4 83 [2] ff cd [2] c2 }

  condition:
    any of them
}