rule TTP_XOR_MULT_DOSStub_0729 {
  strings:
    $key_0729 = { 53 41 [2] 27 59 [2] 60 5b [2] 27 4a [2] 69 46 [2] 65 4c [2] 72 47 [2] 69 09 [2] 54 }

  condition:
    any of them
}