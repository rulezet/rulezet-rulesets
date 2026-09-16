rule TTP_XOR_MULT_DOSStub_475a {
  strings:
    $key_475a = { 13 32 [2] 67 2a [2] 20 28 [2] 67 39 [2] 29 35 [2] 25 3f [2] 32 34 [2] 29 7a [2] 14 }

  condition:
    any of them
}