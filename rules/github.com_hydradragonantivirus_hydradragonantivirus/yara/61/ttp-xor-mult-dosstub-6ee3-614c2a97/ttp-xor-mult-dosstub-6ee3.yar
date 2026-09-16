rule TTP_XOR_MULT_DOSStub_6ee3 {
  strings:
    $key_6ee3 = { 3a 8b [2] 4e 93 [2] 09 91 [2] 4e 80 [2] 00 8c [2] 0c 86 [2] 1b 8d [2] 00 c3 [2] 3d }

  condition:
    any of them
}