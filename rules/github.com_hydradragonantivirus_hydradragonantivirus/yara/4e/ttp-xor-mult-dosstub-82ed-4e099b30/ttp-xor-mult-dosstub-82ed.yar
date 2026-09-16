rule TTP_XOR_MULT_DOSStub_82ed {
  strings:
    $key_82ed = { d6 85 [2] a2 9d [2] e5 9f [2] a2 8e [2] ec 82 [2] e0 88 [2] f7 83 [2] ec cd [2] d1 }

  condition:
    any of them
}