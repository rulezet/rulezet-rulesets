rule TTP_XOR_MULT_DOSStub_161e {
  strings:
    $key_161e = { 42 76 [2] 36 6e [2] 71 6c [2] 36 7d [2] 78 71 [2] 74 7b [2] 63 70 [2] 78 3e [2] 45 }

  condition:
    any of them
}