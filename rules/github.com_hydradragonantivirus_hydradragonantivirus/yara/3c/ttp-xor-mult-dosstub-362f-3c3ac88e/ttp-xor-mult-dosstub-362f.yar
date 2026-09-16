rule TTP_XOR_MULT_DOSStub_362f {
  strings:
    $key_362f = { 62 47 [2] 16 5f [2] 51 5d [2] 16 4c [2] 58 40 [2] 54 4a [2] 43 41 [2] 58 0f [2] 65 }

  condition:
    any of them
}