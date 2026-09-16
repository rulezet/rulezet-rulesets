rule TTP_XOR_MULT_DOSStub_b225 {
  strings:
    $key_b225 = { e6 4d [2] 92 55 [2] d5 57 [2] 92 46 [2] dc 4a [2] d0 40 [2] c7 4b [2] dc 05 [2] e1 }

  condition:
    any of them
}