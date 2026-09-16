rule TTP_XOR_MULT_DOSStub_eda2 {
  strings:
    $key_eda2 = { b9 ca [2] cd d2 [2] 8a d0 [2] cd c1 [2] 83 cd [2] 8f c7 [2] 98 cc [2] 83 82 [2] be }

  condition:
    any of them
}