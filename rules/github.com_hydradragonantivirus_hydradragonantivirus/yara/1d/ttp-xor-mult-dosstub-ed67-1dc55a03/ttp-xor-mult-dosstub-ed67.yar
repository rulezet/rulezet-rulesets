rule TTP_XOR_MULT_DOSStub_ed67 {
  strings:
    $key_ed67 = { b9 0f [2] cd 17 [2] 8a 15 [2] cd 04 [2] 83 08 [2] 8f 02 [2] 98 09 [2] 83 47 [2] be }

  condition:
    any of them
}