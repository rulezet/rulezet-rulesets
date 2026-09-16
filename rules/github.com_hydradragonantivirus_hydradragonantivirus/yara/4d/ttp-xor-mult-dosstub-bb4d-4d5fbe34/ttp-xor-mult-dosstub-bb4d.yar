rule TTP_XOR_MULT_DOSStub_bb4d {
  strings:
    $key_bb4d = { ef 25 [2] 9b 3d [2] dc 3f [2] 9b 2e [2] d5 22 [2] d9 28 [2] ce 23 [2] d5 6d [2] e8 }

  condition:
    any of them
}