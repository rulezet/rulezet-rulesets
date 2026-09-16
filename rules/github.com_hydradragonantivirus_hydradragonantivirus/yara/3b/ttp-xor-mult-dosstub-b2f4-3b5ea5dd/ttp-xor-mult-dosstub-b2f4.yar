rule TTP_XOR_MULT_DOSStub_b2f4 {
  strings:
    $key_b2f4 = { e6 9c [2] 92 84 [2] d5 86 [2] 92 97 [2] dc 9b [2] d0 91 [2] c7 9a [2] dc d4 [2] e1 }

  condition:
    any of them
}