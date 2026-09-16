rule TTP_XOR_MULT_DOSStub_b237 {
  strings:
    $key_b237 = { e6 5f [2] 92 47 [2] d5 45 [2] 92 54 [2] dc 58 [2] d0 52 [2] c7 59 [2] dc 17 [2] e1 }

  condition:
    any of them
}