rule TTP_XOR_QUAD_CurrentVersionRun_633f {
  strings:
    $key_633f = { 30 50 [2] 14 5e [2] 3f 72 [2] 11 50 [2] 05 4b [2] 0a 51 [2] 14 4c [2] 16 4d [2] 0d 4b [2] 11 4c [2] 0d 63 }

  condition:
    any of them
}