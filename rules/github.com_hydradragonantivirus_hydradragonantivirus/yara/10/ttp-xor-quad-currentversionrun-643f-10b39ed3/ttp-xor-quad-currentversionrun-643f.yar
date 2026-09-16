rule TTP_XOR_QUAD_CurrentVersionRun_643f {
  strings:
    $key_643f = { 37 50 [2] 13 5e [2] 38 72 [2] 16 50 [2] 02 4b [2] 0d 51 [2] 13 4c [2] 11 4d [2] 0a 4b [2] 16 4c [2] 0a 63 }

  condition:
    any of them
}