rule TTP_XOR_MULT_DOSStub_7b53 {
  strings:
    $key_7b53 = { 2f 3b [2] 5b 23 [2] 1c 21 [2] 5b 30 [2] 15 3c [2] 19 36 [2] 0e 3d [2] 15 73 [2] 28 }

  condition:
    any of them
}