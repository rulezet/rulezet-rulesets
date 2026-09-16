rule TTP_XOR_MULT_DOSStub_d63b {
  strings:
    $key_d63b = { 82 53 [2] f6 4b [2] b1 49 [2] f6 58 [2] b8 54 [2] b4 5e [2] a3 55 [2] b8 1b [2] 85 }

  condition:
    any of them
}