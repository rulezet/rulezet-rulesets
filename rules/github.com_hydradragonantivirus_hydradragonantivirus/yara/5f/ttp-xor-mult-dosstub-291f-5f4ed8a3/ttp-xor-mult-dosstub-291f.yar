rule TTP_XOR_MULT_DOSStub_291f {
  strings:
    $key_291f = { 7d 77 [2] 09 6f [2] 4e 6d [2] 09 7c [2] 47 70 [2] 4b 7a [2] 5c 71 [2] 47 3f [2] 7a }

  condition:
    any of them
}