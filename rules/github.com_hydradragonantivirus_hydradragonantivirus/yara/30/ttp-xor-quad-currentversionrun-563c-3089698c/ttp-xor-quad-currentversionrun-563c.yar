rule TTP_XOR_QUAD_CurrentVersionRun_563c {
  strings:
    $key_563c = { 05 53 [2] 21 5d [2] 0a 71 [2] 24 53 [2] 30 48 [2] 3f 52 [2] 21 4f [2] 23 4e [2] 38 48 [2] 24 4f [2] 38 60 }

  condition:
    any of them
}