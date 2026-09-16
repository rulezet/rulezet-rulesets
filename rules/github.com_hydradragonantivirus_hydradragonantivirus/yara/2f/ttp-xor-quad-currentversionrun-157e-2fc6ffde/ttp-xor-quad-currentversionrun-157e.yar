rule TTP_XOR_QUAD_CurrentVersionRun_157e {
  strings:
    $key_157e = { 46 11 [2] 62 1f [2] 49 33 [2] 67 11 [2] 73 0a [2] 7c 10 [2] 62 0d [2] 60 0c [2] 7b 0a [2] 67 0d [2] 7b 22 }

  condition:
    any of them
}