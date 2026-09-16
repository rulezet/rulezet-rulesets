rule TTP_XOR_MULT_DOSStub_132a {
  strings:
    $key_132a = { 47 42 [2] 33 5a [2] 74 58 [2] 33 49 [2] 7d 45 [2] 71 4f [2] 66 44 [2] 7d 0a [2] 40 }

  condition:
    any of them
}