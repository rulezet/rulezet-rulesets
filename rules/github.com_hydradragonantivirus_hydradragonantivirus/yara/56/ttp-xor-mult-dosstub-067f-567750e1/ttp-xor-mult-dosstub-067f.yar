rule TTP_XOR_MULT_DOSStub_067f {
  strings:
    $key_067f = { 52 17 [2] 26 0f [2] 61 0d [2] 26 1c [2] 68 10 [2] 64 1a [2] 73 11 [2] 68 5f [2] 55 }

  condition:
    any of them
}