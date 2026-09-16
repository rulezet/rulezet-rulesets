rule TTP_XOR_QUAD_CurrentVersionRun_357e {
  strings:
    $key_357e = { 66 11 [2] 42 1f [2] 69 33 [2] 47 11 [2] 53 0a [2] 5c 10 [2] 42 0d [2] 40 0c [2] 5b 0a [2] 47 0d [2] 5b 22 }

  condition:
    any of them
}