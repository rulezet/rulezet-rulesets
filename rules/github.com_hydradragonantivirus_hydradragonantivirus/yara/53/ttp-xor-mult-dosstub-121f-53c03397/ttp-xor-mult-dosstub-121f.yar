rule TTP_XOR_MULT_DOSStub_121f {
  strings:
    $key_121f = { 46 77 [2] 32 6f [2] 75 6d [2] 32 7c [2] 7c 70 [2] 70 7a [2] 67 71 [2] 7c 3f [2] 41 }

  condition:
    any of them
}