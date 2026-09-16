rule TTP_XOR_MULT_DOSStub_48e3 {
  strings:
    $key_48e3 = { 1c 8b [2] 68 93 [2] 2f 91 [2] 68 80 [2] 26 8c [2] 2a 86 [2] 3d 8d [2] 26 c3 [2] 1b }

  condition:
    any of them
}