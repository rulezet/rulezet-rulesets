rule TTP_XOR_MULT_DOSStub_6ef2 {
  strings:
    $key_6ef2 = { 3a 9a [2] 4e 82 [2] 09 80 [2] 4e 91 [2] 00 9d [2] 0c 97 [2] 1b 9c [2] 00 d2 [2] 3d }

  condition:
    any of them
}