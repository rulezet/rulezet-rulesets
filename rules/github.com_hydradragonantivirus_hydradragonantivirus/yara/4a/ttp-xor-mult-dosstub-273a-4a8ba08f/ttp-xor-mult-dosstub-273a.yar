rule TTP_XOR_MULT_DOSStub_273a {
  strings:
    $key_273a = { 73 52 [2] 07 4a [2] 40 48 [2] 07 59 [2] 49 55 [2] 45 5f [2] 52 54 [2] 49 1a [2] 74 }

  condition:
    any of them
}