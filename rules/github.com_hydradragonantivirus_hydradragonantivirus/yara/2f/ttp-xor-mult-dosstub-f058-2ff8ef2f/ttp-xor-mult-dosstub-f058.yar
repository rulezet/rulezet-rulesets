rule TTP_XOR_MULT_DOSStub_f058 {
  strings:
    $key_f058 = { a4 30 [2] d0 28 [2] 97 2a [2] d0 3b [2] 9e 37 [2] 92 3d [2] 85 36 [2] 9e 78 [2] a3 }

  condition:
    any of them
}