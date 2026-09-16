rule TTP_XOR_MULT_DOSStub_481e {
  strings:
    $key_481e = { 1c 76 [2] 68 6e [2] 2f 6c [2] 68 7d [2] 26 71 [2] 2a 7b [2] 3d 70 [2] 26 3e [2] 1b }

  condition:
    any of them
}