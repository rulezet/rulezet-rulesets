rule TTP_XOR_MULT_DOSStub_272c {
  strings:
    $key_272c = { 73 44 [2] 07 5c [2] 40 5e [2] 07 4f [2] 49 43 [2] 45 49 [2] 52 42 [2] 49 0c [2] 74 }

  condition:
    any of them
}