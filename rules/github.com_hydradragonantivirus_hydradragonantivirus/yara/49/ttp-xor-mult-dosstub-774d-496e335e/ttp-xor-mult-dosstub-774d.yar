rule TTP_XOR_MULT_DOSStub_774d {
  strings:
    $key_774d = { 23 25 [2] 57 3d [2] 10 3f [2] 57 2e [2] 19 22 [2] 15 28 [2] 02 23 [2] 19 6d [2] 24 }

  condition:
    any of them
}