rule TTP_XOR_MULT_DOSStub_2729 {
  strings:
    $key_2729 = { 73 41 [2] 07 59 [2] 40 5b [2] 07 4a [2] 49 46 [2] 45 4c [2] 52 47 [2] 49 09 [2] 74 }

  condition:
    any of them
}