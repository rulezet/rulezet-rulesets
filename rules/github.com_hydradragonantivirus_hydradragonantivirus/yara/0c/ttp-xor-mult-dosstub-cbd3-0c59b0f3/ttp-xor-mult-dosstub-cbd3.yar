rule TTP_XOR_MULT_DOSStub_cbd3 {
  strings:
    $key_cbd3 = { 9f bb [2] eb a3 [2] ac a1 [2] eb b0 [2] a5 bc [2] a9 b6 [2] be bd [2] a5 f3 [2] 98 }

  condition:
    any of them
}