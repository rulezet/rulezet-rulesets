rule TTP_XOR_MULT_DOSStub_ff22 {
  strings:
    $key_ff22 = { ab 4a [2] df 52 [2] 98 50 [2] df 41 [2] 91 4d [2] 9d 47 [2] 8a 4c [2] 91 02 [2] ac }

  condition:
    any of them
}