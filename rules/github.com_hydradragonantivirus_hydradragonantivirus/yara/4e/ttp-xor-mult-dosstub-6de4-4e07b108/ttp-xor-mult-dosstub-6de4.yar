rule TTP_XOR_MULT_DOSStub_6de4 {
  strings:
    $key_6de4 = { 39 8c [2] 4d 94 [2] 0a 96 [2] 4d 87 [2] 03 8b [2] 0f 81 [2] 18 8a [2] 03 c4 [2] 3e }

  condition:
    any of them
}