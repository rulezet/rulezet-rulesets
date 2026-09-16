rule TTP_XOR_QUAD_CurrentVersionRun_132e {
  strings:
    $key_132e = { 40 41 [2] 64 4f [2] 4f 63 [2] 61 41 [2] 75 5a [2] 7a 40 [2] 64 5d [2] 66 5c [2] 7d 5a [2] 61 5d [2] 7d 72 }

  condition:
    any of them
}