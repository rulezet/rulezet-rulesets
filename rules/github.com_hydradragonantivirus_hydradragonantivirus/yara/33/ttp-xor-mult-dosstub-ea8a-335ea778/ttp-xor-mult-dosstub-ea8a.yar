rule TTP_XOR_MULT_DOSStub_ea8a {
  strings:
    $key_ea8a = { be e2 [2] ca fa [2] 8d f8 [2] ca e9 [2] 84 e5 [2] 88 ef [2] 9f e4 [2] 84 aa [2] b9 }

  condition:
    any of them
}