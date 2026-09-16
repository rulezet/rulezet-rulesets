rule TTP_XOR_MULT_DOSStub_3b1f {
  strings:
    $key_3b1f = { 6f 77 [2] 1b 6f [2] 5c 6d [2] 1b 7c [2] 55 70 [2] 59 7a [2] 4e 71 [2] 55 3f [2] 68 }

  condition:
    any of them
}