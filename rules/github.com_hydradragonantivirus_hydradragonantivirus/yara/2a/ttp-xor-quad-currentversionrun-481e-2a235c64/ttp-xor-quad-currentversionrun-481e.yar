rule TTP_XOR_QUAD_CurrentVersionRun_481e {
  strings:
    $key_481e = { 1b 71 [2] 3f 7f [2] 14 53 [2] 3a 71 [2] 2e 6a [2] 21 70 [2] 3f 6d [2] 3d 6c [2] 26 6a [2] 3a 6d [2] 26 42 }

  condition:
    any of them
}