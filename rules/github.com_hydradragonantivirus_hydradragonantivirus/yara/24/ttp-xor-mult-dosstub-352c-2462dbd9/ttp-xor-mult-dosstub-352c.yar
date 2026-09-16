rule TTP_XOR_MULT_DOSStub_352c {
  strings:
    $key_352c = { 61 44 [2] 15 5c [2] 52 5e [2] 15 4f [2] 5b 43 [2] 57 49 [2] 40 42 [2] 5b 0c [2] 66 }

  condition:
    any of them
}