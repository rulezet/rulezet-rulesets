rule TTP_XOR_MULT_DOSStub_c228 {
  strings:
    $key_c228 = { 96 40 [2] e2 58 [2] a5 5a [2] e2 4b [2] ac 47 [2] a0 4d [2] b7 46 [2] ac 08 [2] 91 }

  condition:
    any of them
}