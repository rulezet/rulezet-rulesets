rule TTP_XOR_MULT_DOSStub_bb3d {
  strings:
    $key_bb3d = { ef 55 [2] 9b 4d [2] dc 4f [2] 9b 5e [2] d5 52 [2] d9 58 [2] ce 53 [2] d5 1d [2] e8 }

  condition:
    any of them
}