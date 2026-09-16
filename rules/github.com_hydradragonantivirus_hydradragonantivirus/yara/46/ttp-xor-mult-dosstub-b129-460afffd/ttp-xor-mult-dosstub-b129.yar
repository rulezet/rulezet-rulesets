rule TTP_XOR_MULT_DOSStub_b129 {
  strings:
    $key_b129 = { e5 41 [2] 91 59 [2] d6 5b [2] 91 4a [2] df 46 [2] d3 4c [2] c4 47 [2] df 09 [2] e2 }

  condition:
    any of them
}