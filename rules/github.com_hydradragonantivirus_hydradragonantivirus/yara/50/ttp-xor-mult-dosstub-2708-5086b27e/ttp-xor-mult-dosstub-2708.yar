rule TTP_XOR_MULT_DOSStub_2708 {
  strings:
    $key_2708 = { 73 60 [2] 07 78 [2] 40 7a [2] 07 6b [2] 49 67 [2] 45 6d [2] 52 66 [2] 49 28 [2] 74 }

  condition:
    any of them
}