rule TTP_XOR_MULT_DOSStub_026b {
  strings:
    $key_026b = { 56 03 [2] 22 1b [2] 65 19 [2] 22 08 [2] 6c 04 [2] 60 0e [2] 77 05 [2] 6c 4b [2] 51 }

  condition:
    any of them
}