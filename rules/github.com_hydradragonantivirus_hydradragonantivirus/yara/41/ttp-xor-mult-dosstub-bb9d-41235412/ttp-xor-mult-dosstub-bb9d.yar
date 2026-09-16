rule TTP_XOR_MULT_DOSStub_bb9d {
  strings:
    $key_bb9d = { ef f5 [2] 9b ed [2] dc ef [2] 9b fe [2] d5 f2 [2] d9 f8 [2] ce f3 [2] d5 bd [2] e8 }

  condition:
    any of them
}