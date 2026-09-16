rule TTP_XOR_MULT_DOSStub_bb6f {
  strings:
    $key_bb6f = { ef 07 [2] 9b 1f [2] dc 1d [2] 9b 0c [2] d5 00 [2] d9 0a [2] ce 01 [2] d5 4f [2] e8 }

  condition:
    any of them
}