rule TTP_XOR_MULT_DOSStub_9fed {
  strings:
    $key_9fed = { cb 85 [2] bf 9d [2] f8 9f [2] bf 8e [2] f1 82 [2] fd 88 [2] ea 83 [2] f1 cd [2] cc }

  condition:
    any of them
}