rule TTP_XOR_MULT_DOSStub_271f {
  strings:
    $key_271f = { 73 77 [2] 07 6f [2] 40 6d [2] 07 7c [2] 49 70 [2] 45 7a [2] 52 71 [2] 49 3f [2] 74 }

  condition:
    any of them
}