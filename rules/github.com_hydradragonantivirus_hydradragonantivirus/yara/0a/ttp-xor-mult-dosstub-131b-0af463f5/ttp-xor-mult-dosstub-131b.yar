rule TTP_XOR_MULT_DOSStub_131b {
  strings:
    $key_131b = { 47 73 [2] 33 6b [2] 74 69 [2] 33 78 [2] 7d 74 [2] 71 7e [2] 66 75 [2] 7d 3b [2] 40 }

  condition:
    any of them
}