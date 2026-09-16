rule TTP_XOR_QUAD_CurrentVersionRun_100f {
  strings:
    $key_100f = { 43 60 [2] 67 6e [2] 4c 42 [2] 62 60 [2] 76 7b [2] 79 61 [2] 67 7c [2] 65 7d [2] 7e 7b [2] 62 7c [2] 7e 53 }

  condition:
    any of them
}