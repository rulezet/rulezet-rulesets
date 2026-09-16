rule TTP_XOR_MULT_DOSStub_6b9d {
  strings:
    $key_6b9d = { 3f f5 [2] 4b ed [2] 0c ef [2] 4b fe [2] 05 f2 [2] 09 f8 [2] 1e f3 [2] 05 bd [2] 38 }

  condition:
    any of them
}