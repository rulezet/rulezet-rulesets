rule TTP_XOR_MULT_DOSStub_cb22 {
  strings:
    $key_cb22 = { 9f 4a [2] eb 52 [2] ac 50 [2] eb 41 [2] a5 4d [2] a9 47 [2] be 4c [2] a5 02 [2] 98 }

  condition:
    any of them
}