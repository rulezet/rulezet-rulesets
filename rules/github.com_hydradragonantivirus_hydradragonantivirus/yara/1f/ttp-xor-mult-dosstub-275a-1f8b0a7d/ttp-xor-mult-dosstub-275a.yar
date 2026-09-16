rule TTP_XOR_MULT_DOSStub_275a {
  strings:
    $key_275a = { 73 32 [2] 07 2a [2] 40 28 [2] 07 39 [2] 49 35 [2] 45 3f [2] 52 34 [2] 49 7a [2] 74 }

  condition:
    any of them
}