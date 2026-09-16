rule TTP_XOR_MULT_DOSStub_b219 {
  strings:
    $key_b219 = { e6 71 [2] 92 69 [2] d5 6b [2] 92 7a [2] dc 76 [2] d0 7c [2] c7 77 [2] dc 39 [2] e1 }

  condition:
    any of them
}