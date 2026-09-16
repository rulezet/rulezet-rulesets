rule TTP_XOR_MULT_DOSStub_027e {
  strings:
    $key_027e = { 56 16 [2] 22 0e [2] 65 0c [2] 22 1d [2] 6c 11 [2] 60 1b [2] 77 10 [2] 6c 5e [2] 51 }

  condition:
    any of them
}