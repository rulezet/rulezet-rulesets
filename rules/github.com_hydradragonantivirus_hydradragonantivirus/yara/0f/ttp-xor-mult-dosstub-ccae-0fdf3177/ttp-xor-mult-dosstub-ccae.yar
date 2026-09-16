rule TTP_XOR_MULT_DOSStub_ccae {
  strings:
    $key_ccae = { 98 c6 [2] ec de [2] ab dc [2] ec cd [2] a2 c1 [2] ae cb [2] b9 c0 [2] a2 8e [2] 9f }

  condition:
    any of them
}