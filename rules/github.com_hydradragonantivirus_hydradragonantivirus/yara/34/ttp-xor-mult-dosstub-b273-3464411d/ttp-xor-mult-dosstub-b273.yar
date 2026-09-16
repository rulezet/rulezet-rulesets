rule TTP_XOR_MULT_DOSStub_b273 {
  strings:
    $key_b273 = { e6 1b [2] 92 03 [2] d5 01 [2] 92 10 [2] dc 1c [2] d0 16 [2] c7 1d [2] dc 53 [2] e1 }

  condition:
    any of them
}