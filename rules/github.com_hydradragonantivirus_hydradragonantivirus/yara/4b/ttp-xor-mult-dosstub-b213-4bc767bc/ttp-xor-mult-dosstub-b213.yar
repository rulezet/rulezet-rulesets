rule TTP_XOR_MULT_DOSStub_b213 {
  strings:
    $key_b213 = { e6 7b [2] 92 63 [2] d5 61 [2] 92 70 [2] dc 7c [2] d0 76 [2] c7 7d [2] dc 33 [2] e1 }

  condition:
    any of them
}