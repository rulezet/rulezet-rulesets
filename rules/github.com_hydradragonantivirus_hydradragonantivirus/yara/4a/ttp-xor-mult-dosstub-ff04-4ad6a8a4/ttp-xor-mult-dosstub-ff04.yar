rule TTP_XOR_MULT_DOSStub_ff04 {
  strings:
    $key_ff04 = { ab 6c [2] df 74 [2] 98 76 [2] df 67 [2] 91 6b [2] 9d 61 [2] 8a 6a [2] 91 24 [2] ac }

  condition:
    any of them
}