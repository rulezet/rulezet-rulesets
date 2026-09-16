rule TTP_XOR_MULT_DOSStub_48fc {
  strings:
    $key_48fc = { 1c 94 [2] 68 8c [2] 2f 8e [2] 68 9f [2] 26 93 [2] 2a 99 [2] 3d 92 [2] 26 dc [2] 1b }

  condition:
    any of them
}