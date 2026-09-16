rule TTP_XOR_MULT_DOSStub_fd04 {
  strings:
    $key_fd04 = { a9 6c [2] dd 74 [2] 9a 76 [2] dd 67 [2] 93 6b [2] 9f 61 [2] 88 6a [2] 93 24 [2] ae }

  condition:
    any of them
}