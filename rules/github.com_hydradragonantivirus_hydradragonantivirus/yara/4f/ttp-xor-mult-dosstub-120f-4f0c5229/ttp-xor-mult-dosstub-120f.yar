rule TTP_XOR_MULT_DOSStub_120f {
  strings:
    $key_120f = { 46 67 [2] 32 7f [2] 75 7d [2] 32 6c [2] 7c 60 [2] 70 6a [2] 67 61 [2] 7c 2f [2] 41 }

  condition:
    any of them
}