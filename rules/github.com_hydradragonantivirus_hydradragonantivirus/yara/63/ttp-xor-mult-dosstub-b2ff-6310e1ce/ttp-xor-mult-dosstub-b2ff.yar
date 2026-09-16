rule TTP_XOR_MULT_DOSStub_b2ff {
  strings:
    $key_b2ff = { e6 97 [2] 92 8f [2] d5 8d [2] 92 9c [2] dc 90 [2] d0 9a [2] c7 91 [2] dc df [2] e1 }

  condition:
    any of them
}