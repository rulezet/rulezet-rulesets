rule TTP_XOR_MULT_DOSStub_b729 {
  strings:
    $key_b729 = { e3 41 [2] 97 59 [2] d0 5b [2] 97 4a [2] d9 46 [2] d5 4c [2] c2 47 [2] d9 09 [2] e4 }

  condition:
    any of them
}