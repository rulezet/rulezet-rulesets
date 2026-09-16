rule TTP_XOR_QUAD_CurrentVersionRun_144c {
  strings:
    $key_144c = { 47 23 [2] 63 2d [2] 48 01 [2] 66 23 [2] 72 38 [2] 7d 22 [2] 63 3f [2] 61 3e [2] 7a 38 [2] 66 3f [2] 7a 10 }

  condition:
    any of them
}