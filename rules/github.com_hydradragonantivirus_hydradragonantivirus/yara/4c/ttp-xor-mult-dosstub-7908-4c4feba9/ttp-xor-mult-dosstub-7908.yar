rule TTP_XOR_MULT_DOSStub_7908 {
  strings:
    $key_7908 = { 2d 60 [2] 59 78 [2] 1e 7a [2] 59 6b [2] 17 67 [2] 1b 6d [2] 0c 66 [2] 17 28 [2] 2a }

  condition:
    any of them
}