rule TTP_XOR_MULT_DOSStub_d62d {
  strings:
    $key_d62d = { 82 45 [2] f6 5d [2] b1 5f [2] f6 4e [2] b8 42 [2] b4 48 [2] a3 43 [2] b8 0d [2] 85 }

  condition:
    any of them
}