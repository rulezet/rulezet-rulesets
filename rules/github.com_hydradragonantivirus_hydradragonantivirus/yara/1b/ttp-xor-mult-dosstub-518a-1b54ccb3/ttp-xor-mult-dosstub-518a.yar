rule TTP_XOR_MULT_DOSStub_518a {
  strings:
    $key_518a = { 05 e2 [2] 71 fa [2] 36 f8 [2] 71 e9 [2] 3f e5 [2] 33 ef [2] 24 e4 [2] 3f aa [2] 02 }

  condition:
    any of them
}