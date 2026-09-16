rule TTP_XOR_MULT_DOSStub_6b1f {
  strings:
    $key_6b1f = { 3f 77 [2] 4b 6f [2] 0c 6d [2] 4b 7c [2] 05 70 [2] 09 7a [2] 1e 71 [2] 05 3f [2] 38 }

  condition:
    any of them
}