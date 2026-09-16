rule TTP_XOR_MULT_DOSStub_6de5 {
  strings:
    $key_6de5 = { 39 8d [2] 4d 95 [2] 0a 97 [2] 4d 86 [2] 03 8a [2] 0f 80 [2] 18 8b [2] 03 c5 [2] 3e }

  condition:
    any of them
}