rule TTP_XOR_MULT_DOSStub_b221 {
  strings:
    $key_b221 = { e6 49 [2] 92 51 [2] d5 53 [2] 92 42 [2] dc 4e [2] d0 44 [2] c7 4f [2] dc 01 [2] e1 }

  condition:
    any of them
}