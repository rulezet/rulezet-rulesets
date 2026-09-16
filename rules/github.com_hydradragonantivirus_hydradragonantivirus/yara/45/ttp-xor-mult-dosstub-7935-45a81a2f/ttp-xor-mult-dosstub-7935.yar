rule TTP_XOR_MULT_DOSStub_7935 {
  strings:
    $key_7935 = { 2d 5d [2] 59 45 [2] 1e 47 [2] 59 56 [2] 17 5a [2] 1b 50 [2] 0c 5b [2] 17 15 [2] 2a }

  condition:
    any of them
}