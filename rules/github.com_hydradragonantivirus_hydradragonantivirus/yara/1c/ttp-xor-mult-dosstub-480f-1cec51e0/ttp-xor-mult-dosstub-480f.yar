rule TTP_XOR_MULT_DOSStub_480f {
  strings:
    $key_480f = { 1c 67 [2] 68 7f [2] 2f 7d [2] 68 6c [2] 26 60 [2] 2a 6a [2] 3d 61 [2] 26 2f [2] 1b }

  condition:
    any of them
}