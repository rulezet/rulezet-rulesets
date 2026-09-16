rule TTP_XOR_QUAD_CurrentVersionRun_6c3c {
  strings:
    $key_6c3c = { 3f 53 [2] 1b 5d [2] 30 71 [2] 1e 53 [2] 0a 48 [2] 05 52 [2] 1b 4f [2] 19 4e [2] 02 48 [2] 1e 4f [2] 02 60 }

  condition:
    any of them
}