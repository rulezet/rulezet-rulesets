rule TTP_XOR_MULT_DOSStub_481b {
  strings:
    $key_481b = { 1c 73 [2] 68 6b [2] 2f 69 [2] 68 78 [2] 26 74 [2] 2a 7e [2] 3d 75 [2] 26 3b [2] 1b }

  condition:
    any of them
}