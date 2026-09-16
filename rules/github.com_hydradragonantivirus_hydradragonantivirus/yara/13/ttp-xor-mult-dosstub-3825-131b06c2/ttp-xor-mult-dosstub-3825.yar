rule TTP_XOR_MULT_DOSStub_3825 {
  strings:
    $key_3825 = { 6c 4d [2] 18 55 [2] 5f 57 [2] 18 46 [2] 56 4a [2] 5a 40 [2] 4d 4b [2] 56 05 [2] 6b }

  condition:
    any of them
}