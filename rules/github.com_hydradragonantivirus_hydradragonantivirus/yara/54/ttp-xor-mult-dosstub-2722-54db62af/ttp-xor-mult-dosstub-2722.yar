rule TTP_XOR_MULT_DOSStub_2722 {
  strings:
    $key_2722 = { 73 4a [2] 07 52 [2] 40 50 [2] 07 41 [2] 49 4d [2] 45 47 [2] 52 4c [2] 49 02 [2] 74 }

  condition:
    any of them
}