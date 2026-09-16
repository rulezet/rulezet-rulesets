rule TTP_XOR_MULT_DOSStub_99dc {
  strings:
    $key_99dc = { cd b4 [2] b9 ac [2] fe ae [2] b9 bf [2] f7 b3 [2] fb b9 [2] ec b2 [2] f7 fc [2] ca }

  condition:
    any of them
}