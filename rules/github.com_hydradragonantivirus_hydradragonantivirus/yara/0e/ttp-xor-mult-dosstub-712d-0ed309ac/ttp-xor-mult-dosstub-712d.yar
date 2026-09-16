rule TTP_XOR_MULT_DOSStub_712d {
  strings:
    $key_712d = { 25 45 [2] 51 5d [2] 16 5f [2] 51 4e [2] 1f 42 [2] 13 48 [2] 04 43 [2] 1f 0d [2] 22 }

  condition:
    any of them
}