rule TTP_XOR_MULT_DOSStub_0a53 {
  strings:
    $key_0a53 = { 5e 3b [2] 2a 23 [2] 6d 21 [2] 2a 30 [2] 64 3c [2] 68 36 [2] 7f 3d [2] 64 73 [2] 59 }

  condition:
    any of them
}