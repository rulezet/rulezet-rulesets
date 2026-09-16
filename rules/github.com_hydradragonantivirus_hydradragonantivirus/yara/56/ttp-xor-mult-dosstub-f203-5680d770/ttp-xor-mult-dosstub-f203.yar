rule TTP_XOR_MULT_DOSStub_f203 {
  strings:
    $key_f203 = { a6 6b [2] d2 73 [2] 95 71 [2] d2 60 [2] 9c 6c [2] 90 66 [2] 87 6d [2] 9c 23 [2] a1 }

  condition:
    any of them
}