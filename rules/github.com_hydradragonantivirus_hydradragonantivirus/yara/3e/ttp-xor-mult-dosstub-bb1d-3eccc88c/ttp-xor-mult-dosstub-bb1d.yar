rule TTP_XOR_MULT_DOSStub_bb1d {
  strings:
    $key_bb1d = { ef 75 [2] 9b 6d [2] dc 6f [2] 9b 7e [2] d5 72 [2] d9 78 [2] ce 73 [2] d5 3d [2] e8 }

  condition:
    any of them
}