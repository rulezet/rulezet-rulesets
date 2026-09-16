rule TTP_XOR_MULT_DOSStub_330f {
  strings:
    $key_330f = { 67 67 [2] 13 7f [2] 54 7d [2] 13 6c [2] 5d 60 [2] 51 6a [2] 46 61 [2] 5d 2f [2] 60 }

  condition:
    any of them
}