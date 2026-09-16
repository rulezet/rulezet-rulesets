rule TTP_XOR_MULT_DOSStub_31be {
  strings:
    $key_31be = { 65 d6 [2] 11 ce [2] 56 cc [2] 11 dd [2] 5f d1 [2] 53 db [2] 44 d0 [2] 5f 9e [2] 62 }

  condition:
    any of them
}