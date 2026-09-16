rule TTP_XOR_MULT_DOSStub_b23a {
  strings:
    $key_b23a = { e6 52 [2] 92 4a [2] d5 48 [2] 92 59 [2] dc 55 [2] d0 5f [2] c7 54 [2] dc 1a [2] e1 }

  condition:
    any of them
}