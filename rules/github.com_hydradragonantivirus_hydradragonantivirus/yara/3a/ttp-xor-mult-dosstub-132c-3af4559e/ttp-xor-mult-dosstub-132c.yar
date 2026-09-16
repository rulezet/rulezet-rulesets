rule TTP_XOR_MULT_DOSStub_132c {
  strings:
    $key_132c = { 47 44 [2] 33 5c [2] 74 5e [2] 33 4f [2] 7d 43 [2] 71 49 [2] 66 42 [2] 7d 0c [2] 40 }

  condition:
    any of them
}