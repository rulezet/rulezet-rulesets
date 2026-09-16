rule TTP_XOR_MULT_DOSStub_b2f2 {
  strings:
    $key_b2f2 = { e6 9a [2] 92 82 [2] d5 80 [2] 92 91 [2] dc 9d [2] d0 97 [2] c7 9c [2] dc d2 [2] e1 }

  condition:
    any of them
}