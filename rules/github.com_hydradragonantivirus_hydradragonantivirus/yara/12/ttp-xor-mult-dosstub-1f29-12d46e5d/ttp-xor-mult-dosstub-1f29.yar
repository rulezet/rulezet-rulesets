rule TTP_XOR_MULT_DOSStub_1f29 {
  strings:
    $key_1f29 = { 4b 41 [2] 3f 59 [2] 78 5b [2] 3f 4a [2] 71 46 [2] 7d 4c [2] 6a 47 [2] 71 09 [2] 4c }

  condition:
    any of them
}