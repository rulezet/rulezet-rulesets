rule TTP_XOR_MULT_DOSStub_0603 {
  strings:
    $key_0603 = { 52 6b [2] 26 73 [2] 61 71 [2] 26 60 [2] 68 6c [2] 64 66 [2] 73 6d [2] 68 23 [2] 55 }

  condition:
    any of them
}