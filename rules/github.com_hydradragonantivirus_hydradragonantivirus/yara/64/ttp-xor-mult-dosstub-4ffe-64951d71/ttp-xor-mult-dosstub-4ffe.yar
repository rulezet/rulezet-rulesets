rule TTP_XOR_MULT_DOSStub_4ffe {
  strings:
    $key_4ffe = { 1b 96 [2] 6f 8e [2] 28 8c [2] 6f 9d [2] 21 91 [2] 2d 9b [2] 3a 90 [2] 21 de [2] 1c }

  condition:
    any of them
}