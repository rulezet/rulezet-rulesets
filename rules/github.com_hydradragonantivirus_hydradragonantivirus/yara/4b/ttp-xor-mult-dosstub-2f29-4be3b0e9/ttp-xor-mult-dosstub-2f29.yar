rule TTP_XOR_MULT_DOSStub_2f29 {
  strings:
    $key_2f29 = { 7b 41 [2] 0f 59 [2] 48 5b [2] 0f 4a [2] 41 46 [2] 4d 4c [2] 5a 47 [2] 41 09 [2] 7c }

  condition:
    any of them
}