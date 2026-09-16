rule TTP_XOR_MULT_DOSStub_ff2f {
  strings:
    $key_ff2f = { ab 47 [2] df 5f [2] 98 5d [2] df 4c [2] 91 40 [2] 9d 4a [2] 8a 41 [2] 91 0f [2] ac }

  condition:
    any of them
}