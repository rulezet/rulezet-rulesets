rule TTP_XOR_QUAD_CurrentVersionRun_633c {
  strings:
    $key_633c = { 30 53 [2] 14 5d [2] 3f 71 [2] 11 53 [2] 05 48 [2] 0a 52 [2] 14 4f [2] 16 4e [2] 0d 48 [2] 11 4f [2] 0d 60 }

  condition:
    any of them
}