rule TTP_XOR_MULT_DOSStub_ffe9 {
  strings:
    $key_ffe9 = { ab 81 [2] df 99 [2] 98 9b [2] df 8a [2] 91 86 [2] 9d 8c [2] 8a 87 [2] 91 c9 [2] ac }

  condition:
    any of them
}