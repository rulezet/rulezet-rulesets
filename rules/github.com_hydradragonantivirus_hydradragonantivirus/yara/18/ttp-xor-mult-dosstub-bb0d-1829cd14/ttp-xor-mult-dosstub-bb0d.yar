rule TTP_XOR_MULT_DOSStub_bb0d {
  strings:
    $key_bb0d = { ef 65 [2] 9b 7d [2] dc 7f [2] 9b 6e [2] d5 62 [2] d9 68 [2] ce 63 [2] d5 2d [2] e8 }

  condition:
    any of them
}