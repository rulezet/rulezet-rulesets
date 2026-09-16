rule TTP_XOR_MULT_DOSStub_f24d {
  strings:
    $key_f24d = { a6 25 [2] d2 3d [2] 95 3f [2] d2 2e [2] 9c 22 [2] 90 28 [2] 87 23 [2] 9c 6d [2] a1 }

  condition:
    any of them
}