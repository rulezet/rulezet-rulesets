rule TTP_XOR_MULT_DOSStub_f614 {
  strings:
    $key_f614 = { a2 7c [2] d6 64 [2] 91 66 [2] d6 77 [2] 98 7b [2] 94 71 [2] 83 7a [2] 98 34 [2] a5 }

  condition:
    any of them
}