rule TTP_XOR_QUAD_CurrentVersionRun_217e {
  strings:
    $key_217e = { 72 11 [2] 56 1f [2] 7d 33 [2] 53 11 [2] 47 0a [2] 48 10 [2] 56 0d [2] 54 0c [2] 4f 0a [2] 53 0d [2] 4f 22 }

  condition:
    any of them
}