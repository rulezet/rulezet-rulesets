rule TTP_XOR_MULT_DOSStub_cbed {
  strings:
    $key_cbed = { 9f 85 [2] eb 9d [2] ac 9f [2] eb 8e [2] a5 82 [2] a9 88 [2] be 83 [2] a5 cd [2] 98 }

  condition:
    any of them
}