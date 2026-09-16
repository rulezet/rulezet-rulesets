rule TTP_XOR_MULT_DOSStub_bbe6 {
  strings:
    $key_bbe6 = { ef 8e [2] 9b 96 [2] dc 94 [2] 9b 85 [2] d5 89 [2] d9 83 [2] ce 88 [2] d5 c6 [2] e8 }

  condition:
    any of them
}