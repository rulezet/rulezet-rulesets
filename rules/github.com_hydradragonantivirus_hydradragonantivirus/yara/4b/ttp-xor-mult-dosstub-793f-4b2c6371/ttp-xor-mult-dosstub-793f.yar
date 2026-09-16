rule TTP_XOR_MULT_DOSStub_793f {
  strings:
    $key_793f = { 2d 57 [2] 59 4f [2] 1e 4d [2] 59 5c [2] 17 50 [2] 1b 5a [2] 0c 51 [2] 17 1f [2] 2a }

  condition:
    any of them
}