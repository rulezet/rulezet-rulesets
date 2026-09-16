rule TTP_XOR_MULT_DOSStub_b210 {
  strings:
    $key_b210 = { e6 78 [2] 92 60 [2] d5 62 [2] 92 73 [2] dc 7f [2] d0 75 [2] c7 7e [2] dc 30 [2] e1 }

  condition:
    any of them
}