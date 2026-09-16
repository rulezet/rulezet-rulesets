rule TTP_XOR_QUAD_CurrentVersionRun_3d2e {
  strings:
    $key_3d2e = { 6e 41 [2] 4a 4f [2] 61 63 [2] 4f 41 [2] 5b 5a [2] 54 40 [2] 4a 5d [2] 48 5c [2] 53 5a [2] 4f 5d [2] 53 72 }

  condition:
    any of them
}