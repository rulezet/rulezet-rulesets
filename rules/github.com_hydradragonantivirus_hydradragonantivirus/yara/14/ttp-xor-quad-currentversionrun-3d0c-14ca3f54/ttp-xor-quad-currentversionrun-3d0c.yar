rule TTP_XOR_QUAD_CurrentVersionRun_3d0c {
  strings:
    $key_3d0c = { 6e 63 [2] 4a 6d [2] 61 41 [2] 4f 63 [2] 5b 78 [2] 54 62 [2] 4a 7f [2] 48 7e [2] 53 78 [2] 4f 7f [2] 53 50 }

  condition:
    any of them
}