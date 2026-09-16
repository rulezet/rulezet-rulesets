rule TTP_XOR_MULT_DOSStub_b53a {
  strings:
    $key_b53a = { e1 52 [2] 95 4a [2] d2 48 [2] 95 59 [2] db 55 [2] d7 5f [2] c0 54 [2] db 1a [2] e6 }

  condition:
    any of them
}