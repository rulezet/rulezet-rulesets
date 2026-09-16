rule TTP_XOR_MULT_DOSStub_6d2f {
  strings:
    $key_6d2f = { 39 47 [2] 4d 5f [2] 0a 5d [2] 4d 4c [2] 03 40 [2] 0f 4a [2] 18 41 [2] 03 0f [2] 3e }

  condition:
    any of them
}