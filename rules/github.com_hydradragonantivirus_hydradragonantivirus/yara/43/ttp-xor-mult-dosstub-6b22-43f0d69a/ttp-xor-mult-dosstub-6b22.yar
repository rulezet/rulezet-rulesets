rule TTP_XOR_MULT_DOSStub_6b22 {
  strings:
    $key_6b22 = { 3f 4a [2] 4b 52 [2] 0c 50 [2] 4b 41 [2] 05 4d [2] 09 47 [2] 1e 4c [2] 05 02 [2] 38 }

  condition:
    any of them
}