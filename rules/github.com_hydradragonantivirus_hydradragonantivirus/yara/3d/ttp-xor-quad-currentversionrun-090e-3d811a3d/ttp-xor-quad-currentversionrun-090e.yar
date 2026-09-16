rule TTP_XOR_QUAD_CurrentVersionRun_090e {
  strings:
    $key_090e = { 5a 61 [2] 7e 6f [2] 55 43 [2] 7b 61 [2] 6f 7a [2] 60 60 [2] 7e 7d [2] 7c 7c [2] 67 7a [2] 7b 7d [2] 67 52 }

  condition:
    any of them
}