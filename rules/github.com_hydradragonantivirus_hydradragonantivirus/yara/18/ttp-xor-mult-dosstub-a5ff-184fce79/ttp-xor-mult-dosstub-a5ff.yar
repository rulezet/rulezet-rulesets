rule TTP_XOR_MULT_DOSStub_a5ff {
  strings:
    $key_a5ff = { f1 97 [2] 85 8f [2] c2 8d [2] 85 9c [2] cb 90 [2] c7 9a [2] d0 91 [2] cb df [2] f6 }

  condition:
    any of them
}