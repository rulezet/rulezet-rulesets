rule TTP_XOR_MULT_DOSStub_615a {
  strings:
    $key_615a = { 35 32 [2] 41 2a [2] 06 28 [2] 41 39 [2] 0f 35 [2] 03 3f [2] 14 34 [2] 0f 7a [2] 32 }

  condition:
    any of them
}