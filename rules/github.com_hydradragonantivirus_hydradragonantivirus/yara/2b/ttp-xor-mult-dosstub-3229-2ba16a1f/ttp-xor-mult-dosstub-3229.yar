rule TTP_XOR_MULT_DOSStub_3229 {
  strings:
    $key_3229 = { 66 41 [2] 12 59 [2] 55 5b [2] 12 4a [2] 5c 46 [2] 50 4c [2] 47 47 [2] 5c 09 [2] 61 }

  condition:
    any of them
}