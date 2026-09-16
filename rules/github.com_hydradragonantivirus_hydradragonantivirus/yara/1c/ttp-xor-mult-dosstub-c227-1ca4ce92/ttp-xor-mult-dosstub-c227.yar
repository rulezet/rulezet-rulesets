rule TTP_XOR_MULT_DOSStub_c227 {
  strings:
    $key_c227 = { 96 4f [2] e2 57 [2] a5 55 [2] e2 44 [2] ac 48 [2] a0 42 [2] b7 49 [2] ac 07 [2] 91 }

  condition:
    any of them
}