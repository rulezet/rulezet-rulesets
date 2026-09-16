rule TTP_XOR_MULT_DOSStub_131a {
  strings:
    $key_131a = { 47 72 [2] 33 6a [2] 74 68 [2] 33 79 [2] 7d 75 [2] 71 7f [2] 66 74 [2] 7d 3a [2] 40 }

  condition:
    any of them
}