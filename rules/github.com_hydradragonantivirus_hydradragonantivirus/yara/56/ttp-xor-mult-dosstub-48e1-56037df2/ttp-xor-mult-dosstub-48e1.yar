rule TTP_XOR_MULT_DOSStub_48e1 {
  strings:
    $key_48e1 = { 1c 89 [2] 68 91 [2] 2f 93 [2] 68 82 [2] 26 8e [2] 2a 84 [2] 3d 8f [2] 26 c1 [2] 1b }

  condition:
    any of them
}