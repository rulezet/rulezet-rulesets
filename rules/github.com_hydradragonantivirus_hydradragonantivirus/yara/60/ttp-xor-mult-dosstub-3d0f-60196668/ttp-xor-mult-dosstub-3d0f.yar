rule TTP_XOR_MULT_DOSStub_3d0f {
  strings:
    $key_3d0f = { 69 67 [2] 1d 7f [2] 5a 7d [2] 1d 6c [2] 53 60 [2] 5f 6a [2] 48 61 [2] 53 2f [2] 6e }

  condition:
    any of them
}