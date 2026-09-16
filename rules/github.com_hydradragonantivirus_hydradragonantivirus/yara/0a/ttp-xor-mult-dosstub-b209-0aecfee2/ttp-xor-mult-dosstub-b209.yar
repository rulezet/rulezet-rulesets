rule TTP_XOR_MULT_DOSStub_b209 {
  strings:
    $key_b209 = { e6 61 [2] 92 79 [2] d5 7b [2] 92 6a [2] dc 66 [2] d0 6c [2] c7 67 [2] dc 29 [2] e1 }

  condition:
    any of them
}