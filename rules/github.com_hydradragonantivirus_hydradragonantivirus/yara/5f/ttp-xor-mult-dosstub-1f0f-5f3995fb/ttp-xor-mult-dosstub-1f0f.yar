rule TTP_XOR_MULT_DOSStub_1f0f {
  strings:
    $key_1f0f = { 4b 67 [2] 3f 7f [2] 78 7d [2] 3f 6c [2] 71 60 [2] 7d 6a [2] 6a 61 [2] 71 2f [2] 4c }

  condition:
    any of them
}