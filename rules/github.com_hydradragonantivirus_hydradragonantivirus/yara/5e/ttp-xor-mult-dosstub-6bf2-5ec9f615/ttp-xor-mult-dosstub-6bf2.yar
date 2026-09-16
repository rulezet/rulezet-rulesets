rule TTP_XOR_MULT_DOSStub_6bf2 {
  strings:
    $key_6bf2 = { 3f 9a [2] 4b 82 [2] 0c 80 [2] 4b 91 [2] 05 9d [2] 09 97 [2] 1e 9c [2] 05 d2 [2] 38 }

  condition:
    any of them
}