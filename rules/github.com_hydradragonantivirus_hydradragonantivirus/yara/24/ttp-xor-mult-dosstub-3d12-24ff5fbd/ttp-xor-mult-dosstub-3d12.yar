rule TTP_XOR_MULT_DOSStub_3d12 {
  strings:
    $key_3d12 = { 69 7a [2] 1d 62 [2] 5a 60 [2] 1d 71 [2] 53 7d [2] 5f 77 [2] 48 7c [2] 53 32 [2] 6e }

  condition:
    any of them
}