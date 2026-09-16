rule TTP_XOR_MULT_DOSStub_0912 {
  strings:
    $key_0912 = { 5d 7a [2] 29 62 [2] 6e 60 [2] 29 71 [2] 67 7d [2] 6b 77 [2] 7c 7c [2] 67 32 [2] 5a }

  condition:
    any of them
}