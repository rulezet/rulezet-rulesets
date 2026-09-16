rule TTP_XOR_MULT_DOSStub_026a {
  strings:
    $key_026a = { 56 02 [2] 22 1a [2] 65 18 [2] 22 09 [2] 6c 05 [2] 60 0f [2] 77 04 [2] 6c 4a [2] 51 }

  condition:
    any of them
}