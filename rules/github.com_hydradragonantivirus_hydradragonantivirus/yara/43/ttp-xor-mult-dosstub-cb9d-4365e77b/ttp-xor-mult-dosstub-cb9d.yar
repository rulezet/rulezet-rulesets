rule TTP_XOR_MULT_DOSStub_cb9d {
  strings:
    $key_cb9d = { 9f f5 [2] eb ed [2] ac ef [2] eb fe [2] a5 f2 [2] a9 f8 [2] be f3 [2] a5 bd [2] 98 }

  condition:
    any of them
}