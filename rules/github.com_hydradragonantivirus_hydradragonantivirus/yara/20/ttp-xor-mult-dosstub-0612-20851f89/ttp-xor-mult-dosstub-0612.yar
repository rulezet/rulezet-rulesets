rule TTP_XOR_MULT_DOSStub_0612 {
  strings:
    $key_0612 = { 52 7a [2] 26 62 [2] 61 60 [2] 26 71 [2] 68 7d [2] 64 77 [2] 73 7c [2] 68 32 [2] 55 }

  condition:
    any of them
}