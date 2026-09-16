rule TTP_XOR_MULT_DOSStub_ffe2 {
  strings:
    $key_ffe2 = { ab 8a [2] df 92 [2] 98 90 [2] df 81 [2] 91 8d [2] 9d 87 [2] 8a 8c [2] 91 c2 [2] ac }

  condition:
    any of them
}