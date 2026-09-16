rule TTP_XOR_MULT_DOSStub_6de3 {
  strings:
    $key_6de3 = { 39 8b [2] 4d 93 [2] 0a 91 [2] 4d 80 [2] 03 8c [2] 0f 86 [2] 18 8d [2] 03 c3 [2] 3e }

  condition:
    any of them
}