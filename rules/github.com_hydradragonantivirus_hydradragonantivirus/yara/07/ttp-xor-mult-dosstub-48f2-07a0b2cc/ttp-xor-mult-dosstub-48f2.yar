rule TTP_XOR_MULT_DOSStub_48f2 {
  strings:
    $key_48f2 = { 1c 9a [2] 68 82 [2] 2f 80 [2] 68 91 [2] 26 9d [2] 2a 97 [2] 3d 9c [2] 26 d2 [2] 1b }

  condition:
    any of them
}