rule TTP_XOR_QUAD_CurrentVersionRun_176c {
  strings:
    $key_176c = { 44 03 [2] 60 0d [2] 4b 21 [2] 65 03 [2] 71 18 [2] 7e 02 [2] 60 1f [2] 62 1e [2] 79 18 [2] 65 1f [2] 79 30 }

  condition:
    any of them
}