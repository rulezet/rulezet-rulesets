rule TTP_XOR_MULT_DOSStub_485b {
  strings:
    $key_485b = { 1c 33 [2] 68 2b [2] 2f 29 [2] 68 38 [2] 26 34 [2] 2a 3e [2] 3d 35 [2] 26 7b [2] 1b }

  condition:
    any of them
}