rule TTP_XOR_MULT_DOSStub_cb73 {
  strings:
    $key_cb73 = { 9f 1b [2] eb 03 [2] ac 01 [2] eb 10 [2] a5 1c [2] a9 16 [2] be 1d [2] a5 53 [2] 98 }

  condition:
    any of them
}