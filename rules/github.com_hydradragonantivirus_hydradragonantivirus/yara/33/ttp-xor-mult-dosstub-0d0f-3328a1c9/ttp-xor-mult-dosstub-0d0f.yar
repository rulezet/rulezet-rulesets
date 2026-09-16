rule TTP_XOR_MULT_DOSStub_0d0f {
  strings:
    $key_0d0f = { 59 67 [2] 2d 7f [2] 6a 7d [2] 2d 6c [2] 63 60 [2] 6f 6a [2] 78 61 [2] 63 2f [2] 5e }

  condition:
    any of them
}