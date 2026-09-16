rule TTP_XOR_MULT_DOSStub_5ffe {
  strings:
    $key_5ffe = { 0b 96 [2] 7f 8e [2] 38 8c [2] 7f 9d [2] 31 91 [2] 3d 9b [2] 2a 90 [2] 31 de [2] 0c }

  condition:
    any of them
}