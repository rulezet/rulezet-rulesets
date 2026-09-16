rule TTP_XOR_MULT_DOSStub_162c {
  strings:
    $key_162c = { 42 44 [2] 36 5c [2] 71 5e [2] 36 4f [2] 78 43 [2] 74 49 [2] 63 42 [2] 78 0c [2] 45 }

  condition:
    any of them
}