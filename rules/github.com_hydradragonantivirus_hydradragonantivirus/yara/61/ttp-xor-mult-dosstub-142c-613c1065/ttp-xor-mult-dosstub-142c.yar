rule TTP_XOR_MULT_DOSStub_142c {
  strings:
    $key_142c = { 40 44 [2] 34 5c [2] 73 5e [2] 34 4f [2] 7a 43 [2] 76 49 [2] 61 42 [2] 7a 0c [2] 47 }

  condition:
    any of them
}