rule TTP_XOR_MULT_DOSStub_120a {
  strings:
    $key_120a = { 46 62 [2] 32 7a [2] 75 78 [2] 32 69 [2] 7c 65 [2] 70 6f [2] 67 64 [2] 7c 2a [2] 41 }

  condition:
    any of them
}