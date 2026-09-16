rule TTP_XOR_MULT_DOSStub_026c {
  strings:
    $key_026c = { 56 04 [2] 22 1c [2] 65 1e [2] 22 0f [2] 6c 03 [2] 60 09 [2] 77 02 [2] 6c 4c [2] 51 }

  condition:
    any of them
}