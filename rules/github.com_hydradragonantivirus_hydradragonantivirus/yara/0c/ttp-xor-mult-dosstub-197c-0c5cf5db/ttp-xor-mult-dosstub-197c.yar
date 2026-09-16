rule TTP_XOR_MULT_DOSStub_197c {
  strings:
    $key_197c = { 4d 14 [2] 39 0c [2] 7e 0e [2] 39 1f [2] 77 13 [2] 7b 19 [2] 6c 12 [2] 77 5c [2] 4a }

  condition:
    any of them
}