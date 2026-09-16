rule TTP_XOR_MULT_DOSStub_ff1f {
  strings:
    $key_ff1f = { ab 77 [2] df 6f [2] 98 6d [2] df 7c [2] 91 70 [2] 9d 7a [2] 8a 71 [2] 91 3f [2] ac }

  condition:
    any of them
}