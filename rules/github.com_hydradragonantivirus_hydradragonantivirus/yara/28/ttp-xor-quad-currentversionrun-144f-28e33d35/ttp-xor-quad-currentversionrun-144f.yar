rule TTP_XOR_QUAD_CurrentVersionRun_144f {
  strings:
    $key_144f = { 47 20 [2] 63 2e [2] 48 02 [2] 66 20 [2] 72 3b [2] 7d 21 [2] 63 3c [2] 61 3d [2] 7a 3b [2] 66 3c [2] 7a 13 }

  condition:
    any of them
}