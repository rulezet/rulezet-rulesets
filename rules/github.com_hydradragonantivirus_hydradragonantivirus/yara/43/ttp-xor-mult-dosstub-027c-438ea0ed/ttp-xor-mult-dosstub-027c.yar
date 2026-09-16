rule TTP_XOR_MULT_DOSStub_027c {
  strings:
    $key_027c = { 56 14 [2] 22 0c [2] 65 0e [2] 22 1f [2] 6c 13 [2] 60 19 [2] 77 12 [2] 6c 5c [2] 51 }

  condition:
    any of them
}