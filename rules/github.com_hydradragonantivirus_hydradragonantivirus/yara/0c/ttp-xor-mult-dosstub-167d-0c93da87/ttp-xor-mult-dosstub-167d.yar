rule TTP_XOR_MULT_DOSStub_167d {
  strings:
    $key_167d = { 42 15 [2] 36 0d [2] 71 0f [2] 36 1e [2] 78 12 [2] 74 18 [2] 63 13 [2] 78 5d [2] 45 }

  condition:
    any of them
}