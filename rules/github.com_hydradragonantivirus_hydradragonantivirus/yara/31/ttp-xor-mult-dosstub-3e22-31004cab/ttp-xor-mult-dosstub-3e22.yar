rule TTP_XOR_MULT_DOSStub_3e22 {
  strings:
    $key_3e22 = { 6a 4a [2] 1e 52 [2] 59 50 [2] 1e 41 [2] 50 4d [2] 5c 47 [2] 4b 4c [2] 50 02 [2] 6d }

  condition:
    any of them
}