rule TTP_XOR_MULT_DOSStub_2908 {
  strings:
    $key_2908 = { 7d 60 [2] 09 78 [2] 4e 7a [2] 09 6b [2] 47 67 [2] 4b 6d [2] 5c 66 [2] 47 28 [2] 7a }

  condition:
    any of them
}