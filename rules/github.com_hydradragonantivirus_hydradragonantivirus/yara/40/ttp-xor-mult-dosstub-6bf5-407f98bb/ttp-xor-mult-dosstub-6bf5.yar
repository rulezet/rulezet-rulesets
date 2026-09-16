rule TTP_XOR_MULT_DOSStub_6bf5 {
  strings:
    $key_6bf5 = { 3f 9d [2] 4b 85 [2] 0c 87 [2] 4b 96 [2] 05 9a [2] 09 90 [2] 1e 9b [2] 05 d5 [2] 38 }

  condition:
    any of them
}