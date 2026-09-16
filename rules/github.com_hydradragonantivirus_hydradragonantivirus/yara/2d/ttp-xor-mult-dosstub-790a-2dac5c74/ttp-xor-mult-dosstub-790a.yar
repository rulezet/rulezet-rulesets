rule TTP_XOR_MULT_DOSStub_790a {
  strings:
    $key_790a = { 2d 62 [2] 59 7a [2] 1e 78 [2] 59 69 [2] 17 65 [2] 1b 6f [2] 0c 64 [2] 17 2a [2] 2a }

  condition:
    any of them
}