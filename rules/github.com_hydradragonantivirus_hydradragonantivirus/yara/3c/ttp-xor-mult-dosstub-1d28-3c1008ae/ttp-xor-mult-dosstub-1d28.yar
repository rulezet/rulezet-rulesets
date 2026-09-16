rule TTP_XOR_MULT_DOSStub_1d28 {
  strings:
    $key_1d28 = { 49 40 [2] 3d 58 [2] 7a 5a [2] 3d 4b [2] 73 47 [2] 7f 4d [2] 68 46 [2] 73 08 [2] 4e }

  condition:
    any of them
}