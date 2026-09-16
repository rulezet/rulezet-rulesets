rule TTP_XOR_MULT_DOSStub_b267 {
  strings:
    $key_b267 = { e6 0f [2] 92 17 [2] d5 15 [2] 92 04 [2] dc 08 [2] d0 02 [2] c7 09 [2] dc 47 [2] e1 }

  condition:
    any of them
}