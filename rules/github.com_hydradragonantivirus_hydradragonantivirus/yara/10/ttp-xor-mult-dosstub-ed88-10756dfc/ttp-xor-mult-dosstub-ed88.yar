rule TTP_XOR_MULT_DOSStub_ed88 {
  strings:
    $key_ed88 = { b9 e0 [2] cd f8 [2] 8a fa [2] cd eb [2] 83 e7 [2] 8f ed [2] 98 e6 [2] 83 a8 [2] be }

  condition:
    any of them
}