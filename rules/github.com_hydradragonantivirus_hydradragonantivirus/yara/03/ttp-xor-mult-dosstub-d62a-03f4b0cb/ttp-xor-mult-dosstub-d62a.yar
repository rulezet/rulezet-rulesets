rule TTP_XOR_MULT_DOSStub_d62a {
  strings:
    $key_d62a = { 82 42 [2] f6 5a [2] b1 58 [2] f6 49 [2] b8 45 [2] b4 4f [2] a3 44 [2] b8 0a [2] 85 }

  condition:
    any of them
}