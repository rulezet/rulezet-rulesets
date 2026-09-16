rule TTP_XOR_QUAD_CurrentVersionRun_150e {
  strings:
    $key_150e = { 46 61 [2] 62 6f [2] 49 43 [2] 67 61 [2] 73 7a [2] 7c 60 [2] 62 7d [2] 60 7c [2] 7b 7a [2] 67 7d [2] 7b 52 }

  condition:
    any of them
}