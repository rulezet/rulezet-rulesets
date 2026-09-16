rule TTP_XOR_MULT_DOSStub_341b {
  strings:
    $key_341b = { 60 73 [2] 14 6b [2] 53 69 [2] 14 78 [2] 5a 74 [2] 56 7e [2] 41 75 [2] 5a 3b [2] 67 }

  condition:
    any of them
}