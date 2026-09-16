rule TTP_XOR_MULT_DOSStub_c225 {
  strings:
    $key_c225 = { 96 4d [2] e2 55 [2] a5 57 [2] e2 46 [2] ac 4a [2] a0 40 [2] b7 4b [2] ac 05 [2] 91 }

  condition:
    any of them
}