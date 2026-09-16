rule TTP_XOR_MULT_DOSStub_fd29 {
  strings:
    $key_fd29 = { a9 41 [2] dd 59 [2] 9a 5b [2] dd 4a [2] 93 46 [2] 9f 4c [2] 88 47 [2] 93 09 [2] ae }

  condition:
    any of them
}