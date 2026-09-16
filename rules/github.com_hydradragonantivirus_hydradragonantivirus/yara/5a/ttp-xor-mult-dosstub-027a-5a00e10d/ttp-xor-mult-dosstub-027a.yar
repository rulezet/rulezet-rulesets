rule TTP_XOR_MULT_DOSStub_027a {
  strings:
    $key_027a = { 56 12 [2] 22 0a [2] 65 08 [2] 22 19 [2] 6c 15 [2] 60 1f [2] 77 14 [2] 6c 5a [2] 51 }

  condition:
    any of them
}