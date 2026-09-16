rule TTP_XOR_MULT_DOSStub_d72a {
  strings:
    $key_d72a = { 83 42 [2] f7 5a [2] b0 58 [2] f7 49 [2] b9 45 [2] b5 4f [2] a2 44 [2] b9 0a [2] 84 }

  condition:
    any of them
}