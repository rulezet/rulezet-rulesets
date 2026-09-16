rule TTP_XOR_MULT_DOSStub_0b53 {
  strings:
    $key_0b53 = { 5f 3b [2] 2b 23 [2] 6c 21 [2] 2b 30 [2] 65 3c [2] 69 36 [2] 7e 3d [2] 65 73 [2] 58 }

  condition:
    any of them
}