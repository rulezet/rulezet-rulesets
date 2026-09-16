rule TTP_XOR_MULT_DOSStub_998a {
  strings:
    $key_998a = { cd e2 [2] b9 fa [2] fe f8 [2] b9 e9 [2] f7 e5 [2] fb ef [2] ec e4 [2] f7 aa [2] ca }

  condition:
    any of them
}