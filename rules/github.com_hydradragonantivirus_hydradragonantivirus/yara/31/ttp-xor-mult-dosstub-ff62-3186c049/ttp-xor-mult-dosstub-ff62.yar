rule TTP_XOR_MULT_DOSStub_ff62 {
  strings:
    $key_ff62 = { ab 0a [2] df 12 [2] 98 10 [2] df 01 [2] 91 0d [2] 9d 07 [2] 8a 0c [2] 91 42 [2] ac }

  condition:
    any of them
}