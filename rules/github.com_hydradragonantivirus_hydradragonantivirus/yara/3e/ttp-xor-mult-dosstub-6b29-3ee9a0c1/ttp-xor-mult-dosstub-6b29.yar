rule TTP_XOR_MULT_DOSStub_6b29 {
  strings:
    $key_6b29 = { 3f 41 [2] 4b 59 [2] 0c 5b [2] 4b 4a [2] 05 46 [2] 09 4c [2] 1e 47 [2] 05 09 [2] 38 }

  condition:
    any of them
}