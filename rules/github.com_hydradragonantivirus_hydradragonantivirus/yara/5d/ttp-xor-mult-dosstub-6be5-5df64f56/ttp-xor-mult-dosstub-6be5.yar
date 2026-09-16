rule TTP_XOR_MULT_DOSStub_6be5 {
  strings:
    $key_6be5 = { 3f 8d [2] 4b 95 [2] 0c 97 [2] 4b 86 [2] 05 8a [2] 09 80 [2] 1e 8b [2] 05 c5 [2] 38 }

  condition:
    any of them
}