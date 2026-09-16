rule TTP_XOR_QUAD_CurrentVersionRun_352e {
  strings:
    $key_352e = { 66 41 [2] 42 4f [2] 69 63 [2] 47 41 [2] 53 5a [2] 5c 40 [2] 42 5d [2] 40 5c [2] 5b 5a [2] 47 5d [2] 5b 72 }

  condition:
    any of them
}