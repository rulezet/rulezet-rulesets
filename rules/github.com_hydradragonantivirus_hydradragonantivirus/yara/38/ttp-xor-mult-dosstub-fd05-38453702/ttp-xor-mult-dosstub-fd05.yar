rule TTP_XOR_MULT_DOSStub_fd05 {
  strings:
    $key_fd05 = { a9 6d [2] dd 75 [2] 9a 77 [2] dd 66 [2] 93 6a [2] 9f 60 [2] 88 6b [2] 93 25 [2] ae }

  condition:
    any of them
}