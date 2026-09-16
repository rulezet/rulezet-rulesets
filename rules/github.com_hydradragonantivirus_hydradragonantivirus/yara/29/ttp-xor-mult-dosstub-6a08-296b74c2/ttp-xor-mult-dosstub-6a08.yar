rule TTP_XOR_MULT_DOSStub_6a08 {
  strings:
    $key_6a08 = { 3e 60 [2] 4a 78 [2] 0d 7a [2] 4a 6b [2] 04 67 [2] 08 6d [2] 1f 66 [2] 04 28 [2] 39 }

  condition:
    any of them
}