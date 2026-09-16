rule TTP_XOR_MULT_DOSStub_9fbf {
  strings:
    $key_9fbf = { cb d7 [2] bf cf [2] f8 cd [2] bf dc [2] f1 d0 [2] fd da [2] ea d1 [2] f1 9f [2] cc }

  condition:
    any of them
}