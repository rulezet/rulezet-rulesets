rule TTP_XOR_MULT_DOSStub_fff2 {
  strings:
    $key_fff2 = { ab 9a [2] df 82 [2] 98 80 [2] df 91 [2] 91 9d [2] 9d 97 [2] 8a 9c [2] 91 d2 [2] ac }

  condition:
    any of them
}