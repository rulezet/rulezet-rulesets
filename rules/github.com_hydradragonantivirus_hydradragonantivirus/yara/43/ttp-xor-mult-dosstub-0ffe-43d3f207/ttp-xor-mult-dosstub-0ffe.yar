rule TTP_XOR_MULT_DOSStub_0ffe {
  strings:
    $key_0ffe = { 5b 96 [2] 2f 8e [2] 68 8c [2] 2f 9d [2] 61 91 [2] 6d 9b [2] 7a 90 [2] 61 de [2] 5c }

  condition:
    any of them
}