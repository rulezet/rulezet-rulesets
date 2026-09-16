rule TTP_XOR_QUAD_CurrentVersionRun_267e {
  strings:
    $key_267e = { 75 11 [2] 51 1f [2] 7a 33 [2] 54 11 [2] 40 0a [2] 4f 10 [2] 51 0d [2] 53 0c [2] 48 0a [2] 54 0d [2] 48 22 }

  condition:
    any of them
}