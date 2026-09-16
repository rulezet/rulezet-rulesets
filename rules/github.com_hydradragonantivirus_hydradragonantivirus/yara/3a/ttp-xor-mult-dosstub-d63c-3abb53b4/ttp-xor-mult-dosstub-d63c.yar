rule TTP_XOR_MULT_DOSStub_d63c {
  strings:
    $key_d63c = { 82 54 [2] f6 4c [2] b1 4e [2] f6 5f [2] b8 53 [2] b4 59 [2] a3 52 [2] b8 1c [2] 85 }

  condition:
    any of them
}