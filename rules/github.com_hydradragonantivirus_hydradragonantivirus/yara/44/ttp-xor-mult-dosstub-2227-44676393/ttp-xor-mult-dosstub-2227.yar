rule TTP_XOR_MULT_DOSStub_2227 {
  strings:
    $key_2227 = { 76 4f [2] 02 57 [2] 45 55 [2] 02 44 [2] 4c 48 [2] 40 42 [2] 57 49 [2] 4c 07 [2] 71 }

  condition:
    any of them
}