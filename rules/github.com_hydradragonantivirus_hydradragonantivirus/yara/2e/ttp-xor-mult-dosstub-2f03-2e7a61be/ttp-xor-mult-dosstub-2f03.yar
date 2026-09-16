rule TTP_XOR_MULT_DOSStub_2f03 {
  strings:
    $key_2f03 = { 7b 6b [2] 0f 73 [2] 48 71 [2] 0f 60 [2] 41 6c [2] 4d 66 [2] 5a 6d [2] 41 23 [2] 7c }

  condition:
    any of them
}