rule TTP_XOR_QUAD_CurrentVersionRun_483c {
  strings:
    $key_483c = { 1b 53 [2] 3f 5d [2] 14 71 [2] 3a 53 [2] 2e 48 [2] 21 52 [2] 3f 4f [2] 3d 4e [2] 26 48 [2] 3a 4f [2] 26 60 }

  condition:
    any of them
}