rule TTP_XOR_MULT_DOSStub_0f1d {
  strings:
    $key_0f1d = { 5b 75 [2] 2f 6d [2] 68 6f [2] 2f 7e [2] 61 72 [2] 6d 78 [2] 7a 73 [2] 61 3d [2] 5c }

  condition:
    any of them
}