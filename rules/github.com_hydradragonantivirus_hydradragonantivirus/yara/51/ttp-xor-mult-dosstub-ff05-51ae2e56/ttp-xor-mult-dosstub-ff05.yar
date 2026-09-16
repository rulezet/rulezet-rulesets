rule TTP_XOR_MULT_DOSStub_ff05 {
  strings:
    $key_ff05 = { ab 6d [2] df 75 [2] 98 77 [2] df 66 [2] 91 6a [2] 9d 60 [2] 8a 6b [2] 91 25 [2] ac }

  condition:
    any of them
}