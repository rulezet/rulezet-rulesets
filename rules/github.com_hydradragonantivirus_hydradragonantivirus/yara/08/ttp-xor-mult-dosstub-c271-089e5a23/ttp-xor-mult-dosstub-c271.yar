rule TTP_XOR_MULT_DOSStub_c271 {
  strings:
    $key_c271 = { 96 19 [2] e2 01 [2] a5 03 [2] e2 12 [2] ac 1e [2] a0 14 [2] b7 1f [2] ac 51 [2] 91 }

  condition:
    any of them
}