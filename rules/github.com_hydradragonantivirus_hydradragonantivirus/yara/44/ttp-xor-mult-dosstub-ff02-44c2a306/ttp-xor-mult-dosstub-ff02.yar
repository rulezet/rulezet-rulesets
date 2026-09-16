rule TTP_XOR_MULT_DOSStub_ff02 {
  strings:
    $key_ff02 = { ab 6a [2] df 72 [2] 98 70 [2] df 61 [2] 91 6d [2] 9d 67 [2] 8a 6c [2] 91 22 [2] ac }

  condition:
    any of them
}