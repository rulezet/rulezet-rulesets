rule TTP_XOR_MULT_DOSStub_052c {
  strings:
    $key_052c = { 51 44 [2] 25 5c [2] 62 5e [2] 25 4f [2] 6b 43 [2] 67 49 [2] 70 42 [2] 6b 0c [2] 56 }

  condition:
    any of them
}