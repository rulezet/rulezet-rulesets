rule TTP_XOR_MULT_DOSStub_6d0f {
  strings:
    $key_6d0f = { 39 67 [2] 4d 7f [2] 0a 7d [2] 4d 6c [2] 03 60 [2] 0f 6a [2] 18 61 [2] 03 2f [2] 3e }

  condition:
    any of them
}