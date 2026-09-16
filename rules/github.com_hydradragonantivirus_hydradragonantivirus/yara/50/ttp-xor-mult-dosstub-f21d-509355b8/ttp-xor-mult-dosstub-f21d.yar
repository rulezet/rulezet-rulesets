rule TTP_XOR_MULT_DOSStub_f21d {
  strings:
    $key_f21d = { a6 75 [2] d2 6d [2] 95 6f [2] d2 7e [2] 9c 72 [2] 90 78 [2] 87 73 [2] 9c 3d [2] a1 }

  condition:
    any of them
}