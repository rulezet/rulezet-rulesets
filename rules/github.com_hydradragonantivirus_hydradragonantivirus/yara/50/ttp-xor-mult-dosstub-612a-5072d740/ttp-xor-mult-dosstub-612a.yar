rule TTP_XOR_MULT_DOSStub_612a {
  strings:
    $key_612a = { 35 42 [2] 41 5a [2] 06 58 [2] 41 49 [2] 0f 45 [2] 03 4f [2] 14 44 [2] 0f 0a [2] 32 }

  condition:
    any of them
}