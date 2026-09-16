rule TTP_XOR_MULT_DOSStub_483f {
  strings:
    $key_483f = { 1c 57 [2] 68 4f [2] 2f 4d [2] 68 5c [2] 26 50 [2] 2a 5a [2] 3d 51 [2] 26 1f [2] 1b }

  condition:
    any of them
}