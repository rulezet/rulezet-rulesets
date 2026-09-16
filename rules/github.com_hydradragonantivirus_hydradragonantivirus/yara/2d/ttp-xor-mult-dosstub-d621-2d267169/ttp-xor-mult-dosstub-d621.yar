rule TTP_XOR_MULT_DOSStub_d621 {
  strings:
    $key_d621 = { 82 49 [2] f6 51 [2] b1 53 [2] f6 42 [2] b8 4e [2] b4 44 [2] a3 4f [2] b8 01 [2] 85 }

  condition:
    any of them
}