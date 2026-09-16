rule TTP_XOR_MULT_DOSStub_b53c {
  strings:
    $key_b53c = { e1 54 [2] 95 4c [2] d2 4e [2] 95 5f [2] db 53 [2] d7 59 [2] c0 52 [2] db 1c [2] e6 }

  condition:
    any of them
}