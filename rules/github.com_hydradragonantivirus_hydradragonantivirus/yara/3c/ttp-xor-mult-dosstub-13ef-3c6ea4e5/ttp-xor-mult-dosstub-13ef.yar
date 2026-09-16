rule TTP_XOR_MULT_DOSStub_13ef {
  strings:
    $key_13ef = { 47 87 [2] 33 9f [2] 74 9d [2] 33 8c [2] 7d 80 [2] 71 8a [2] 66 81 [2] 7d cf [2] 40 }

  condition:
    any of them
}