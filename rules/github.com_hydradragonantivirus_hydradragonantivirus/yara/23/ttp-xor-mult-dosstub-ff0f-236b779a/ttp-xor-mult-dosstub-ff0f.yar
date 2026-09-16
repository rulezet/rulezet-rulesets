rule TTP_XOR_MULT_DOSStub_ff0f {
  strings:
    $key_ff0f = { ab 67 [2] df 7f [2] 98 7d [2] df 6c [2] 91 60 [2] 9d 6a [2] 8a 61 [2] 91 2f [2] ac }

  condition:
    any of them
}