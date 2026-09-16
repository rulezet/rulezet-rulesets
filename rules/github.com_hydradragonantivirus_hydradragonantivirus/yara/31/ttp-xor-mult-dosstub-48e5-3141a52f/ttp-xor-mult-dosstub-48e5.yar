rule TTP_XOR_MULT_DOSStub_48e5 {
  strings:
    $key_48e5 = { 1c 8d [2] 68 95 [2] 2f 97 [2] 68 86 [2] 26 8a [2] 2a 80 [2] 3d 8b [2] 26 c5 [2] 1b }

  condition:
    any of them
}