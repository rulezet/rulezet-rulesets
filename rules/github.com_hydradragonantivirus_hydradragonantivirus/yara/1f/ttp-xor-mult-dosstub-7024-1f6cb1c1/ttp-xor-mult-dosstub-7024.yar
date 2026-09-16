rule TTP_XOR_MULT_DOSStub_7024 {
  strings:
    $key_7024 = { 24 4c [2] 50 54 [2] 17 56 [2] 50 47 [2] 1e 4b [2] 12 41 [2] 05 4a [2] 1e 04 [2] 23 }

  condition:
    any of them
}