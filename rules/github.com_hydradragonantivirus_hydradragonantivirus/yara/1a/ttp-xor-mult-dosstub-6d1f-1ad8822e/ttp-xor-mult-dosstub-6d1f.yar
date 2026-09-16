rule TTP_XOR_MULT_DOSStub_6d1f {
  strings:
    $key_6d1f = { 39 77 [2] 4d 6f [2] 0a 6d [2] 4d 7c [2] 03 70 [2] 0f 7a [2] 18 71 [2] 03 3f [2] 3e }

  condition:
    any of them
}