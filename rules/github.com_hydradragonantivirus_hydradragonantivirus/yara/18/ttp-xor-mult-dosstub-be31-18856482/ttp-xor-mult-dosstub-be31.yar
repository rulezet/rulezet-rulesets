rule TTP_XOR_MULT_DOSStub_be31 {
  strings:
    $key_be31 = { ea 59 [2] 9e 41 [2] d9 43 [2] 9e 52 [2] d0 5e [2] dc 54 [2] cb 5f [2] d0 11 [2] ed }

  condition:
    any of them
}