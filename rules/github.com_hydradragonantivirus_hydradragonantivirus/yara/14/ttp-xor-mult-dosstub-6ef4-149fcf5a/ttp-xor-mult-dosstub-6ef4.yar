rule TTP_XOR_MULT_DOSStub_6ef4 {
  strings:
    $key_6ef4 = { 3a 9c [2] 4e 84 [2] 09 86 [2] 4e 97 [2] 00 9b [2] 0c 91 [2] 1b 9a [2] 00 d4 [2] 3d }

  condition:
    any of them
}