rule TTP_XOR_MULT_DOSStub_1ff2 {
  strings:
    $key_1ff2 = { 4b 9a [2] 3f 82 [2] 78 80 [2] 3f 91 [2] 71 9d [2] 7d 97 [2] 6a 9c [2] 71 d2 [2] 4c }

  condition:
    any of them
}