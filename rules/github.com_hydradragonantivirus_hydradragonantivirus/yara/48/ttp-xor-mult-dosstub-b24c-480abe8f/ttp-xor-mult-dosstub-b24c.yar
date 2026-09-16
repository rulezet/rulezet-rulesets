rule TTP_XOR_MULT_DOSStub_b24c {
  strings:
    $key_b24c = { e6 24 [2] 92 3c [2] d5 3e [2] 92 2f [2] dc 23 [2] d0 29 [2] c7 22 [2] dc 6c [2] e1 }

  condition:
    any of them
}