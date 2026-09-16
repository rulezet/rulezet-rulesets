rule TTP_XOR_MULT_DOSStub_b20a {
  strings:
    $key_b20a = { e6 62 [2] 92 7a [2] d5 78 [2] 92 69 [2] dc 65 [2] d0 6f [2] c7 64 [2] dc 2a [2] e1 }

  condition:
    any of them
}