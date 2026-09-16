rule TTP_XOR_MULT_DOSStub_1f2f {
  strings:
    $key_1f2f = { 4b 47 [2] 3f 5f [2] 78 5d [2] 3f 4c [2] 71 40 [2] 7d 4a [2] 6a 41 [2] 71 0f [2] 4c }

  condition:
    any of them
}