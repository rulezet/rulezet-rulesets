rule TTP_XOR_MULT_DOSStub_bbe1 {
  strings:
    $key_bbe1 = { ef 89 [2] 9b 91 [2] dc 93 [2] 9b 82 [2] d5 8e [2] d9 84 [2] ce 8f [2] d5 c1 [2] e8 }

  condition:
    any of them
}