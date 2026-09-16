rule TTP_XOR_MULT_DOSStub_0229 {
  strings:
    $key_0229 = { 56 41 [2] 22 59 [2] 65 5b [2] 22 4a [2] 6c 46 [2] 60 4c [2] 77 47 [2] 6c 09 [2] 51 }

  condition:
    any of them
}