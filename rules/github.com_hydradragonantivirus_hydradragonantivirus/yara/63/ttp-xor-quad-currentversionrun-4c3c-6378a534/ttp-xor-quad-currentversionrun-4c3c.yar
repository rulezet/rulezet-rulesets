rule TTP_XOR_QUAD_CurrentVersionRun_4c3c {
  strings:
    $key_4c3c = { 1f 53 [2] 3b 5d [2] 10 71 [2] 3e 53 [2] 2a 48 [2] 25 52 [2] 3b 4f [2] 39 4e [2] 22 48 [2] 3e 4f [2] 22 60 }

  condition:
    any of them
}