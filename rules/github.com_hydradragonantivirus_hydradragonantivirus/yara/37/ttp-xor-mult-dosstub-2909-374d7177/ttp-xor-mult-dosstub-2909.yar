rule TTP_XOR_MULT_DOSStub_2909 {
  strings:
    $key_2909 = { 7d 61 [2] 09 79 [2] 4e 7b [2] 09 6a [2] 47 66 [2] 4b 6c [2] 5c 67 [2] 47 29 [2] 7a }

  condition:
    any of them
}