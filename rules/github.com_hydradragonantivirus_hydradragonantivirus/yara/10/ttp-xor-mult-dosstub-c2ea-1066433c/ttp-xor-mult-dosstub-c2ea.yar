rule TTP_XOR_MULT_DOSStub_c2ea {
  strings:
    $key_c2ea = { 96 82 [2] e2 9a [2] a5 98 [2] e2 89 [2] ac 85 [2] a0 8f [2] b7 84 [2] ac ca [2] 91 }

  condition:
    any of them
}