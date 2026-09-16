rule TTP_XOR_MULT_DOSStub_bb1f {
  strings:
    $key_bb1f = { ef 77 [2] 9b 6f [2] dc 6d [2] 9b 7c [2] d5 70 [2] d9 7a [2] ce 71 [2] d5 3f [2] e8 }

  condition:
    any of them
}