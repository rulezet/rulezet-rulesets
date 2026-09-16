rule TTP_XOR_MULT_DOSStub_2728 {
  strings:
    $key_2728 = { 73 40 [2] 07 58 [2] 40 5a [2] 07 4b [2] 49 47 [2] 45 4d [2] 52 46 [2] 49 08 [2] 74 }

  condition:
    any of them
}