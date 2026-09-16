rule TTP_XOR_QUAD_CurrentVersionRun_683f {
  strings:
    $key_683f = { 3b 50 [2] 1f 5e [2] 34 72 [2] 1a 50 [2] 0e 4b [2] 01 51 [2] 1f 4c [2] 1d 4d [2] 06 4b [2] 1a 4c [2] 06 63 }

  condition:
    any of them
}