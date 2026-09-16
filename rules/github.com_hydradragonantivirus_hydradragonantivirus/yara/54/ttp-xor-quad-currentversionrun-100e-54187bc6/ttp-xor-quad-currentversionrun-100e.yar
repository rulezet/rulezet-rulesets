rule TTP_XOR_QUAD_CurrentVersionRun_100e {
  strings:
    $key_100e = { 43 61 [2] 67 6f [2] 4c 43 [2] 62 61 [2] 76 7a [2] 79 60 [2] 67 7d [2] 65 7c [2] 7e 7a [2] 62 7d [2] 7e 52 }

  condition:
    any of them
}