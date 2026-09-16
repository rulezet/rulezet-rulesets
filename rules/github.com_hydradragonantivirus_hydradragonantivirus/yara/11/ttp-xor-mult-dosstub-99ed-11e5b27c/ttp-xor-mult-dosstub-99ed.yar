rule TTP_XOR_MULT_DOSStub_99ed {
  strings:
    $key_99ed = { cd 85 [2] b9 9d [2] fe 9f [2] b9 8e [2] f7 82 [2] fb 88 [2] ec 83 [2] f7 cd [2] ca }

  condition:
    any of them
}