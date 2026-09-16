rule TTP_XOR_MULT_DOSStub_ffec {
  strings:
    $key_ffec = { ab 84 [2] df 9c [2] 98 9e [2] df 8f [2] 91 83 [2] 9d 89 [2] 8a 82 [2] 91 cc [2] ac }

  condition:
    any of them
}