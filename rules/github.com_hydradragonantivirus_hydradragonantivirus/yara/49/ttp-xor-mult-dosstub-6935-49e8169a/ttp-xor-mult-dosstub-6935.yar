rule TTP_XOR_MULT_DOSStub_6935 {
  strings:
    $key_6935 = { 3d 5d [2] 49 45 [2] 0e 47 [2] 49 56 [2] 07 5a [2] 0b 50 [2] 1c 5b [2] 07 15 [2] 3a }

  condition:
    any of them
}