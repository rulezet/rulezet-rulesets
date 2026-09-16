rule TTP_XOR_MULT_DOSStub_164c {
  strings:
    $key_164c = { 42 24 [2] 36 3c [2] 71 3e [2] 36 2f [2] 78 23 [2] 74 29 [2] 63 22 [2] 78 6c [2] 45 }

  condition:
    any of them
}