rule TTP_XOR_MULT_DOSStub_487a {
  strings:
    $key_487a = { 1c 12 [2] 68 0a [2] 2f 08 [2] 68 19 [2] 26 15 [2] 2a 1f [2] 3d 14 [2] 26 5a [2] 1b }

  condition:
    any of them
}