rule TTP_XOR_MULT_DOSStub_f61b {
  strings:
    $key_f61b = { a2 73 [2] d6 6b [2] 91 69 [2] d6 78 [2] 98 74 [2] 94 7e [2] 83 75 [2] 98 3b [2] a5 }

  condition:
    any of them
}