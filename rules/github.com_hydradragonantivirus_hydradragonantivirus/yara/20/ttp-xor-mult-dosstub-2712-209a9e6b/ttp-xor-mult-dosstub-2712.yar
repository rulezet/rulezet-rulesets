rule TTP_XOR_MULT_DOSStub_2712 {
  strings:
    $key_2712 = { 73 7a [2] 07 62 [2] 40 60 [2] 07 71 [2] 49 7d [2] 45 77 [2] 52 7c [2] 49 32 [2] 74 }

  condition:
    any of them
}