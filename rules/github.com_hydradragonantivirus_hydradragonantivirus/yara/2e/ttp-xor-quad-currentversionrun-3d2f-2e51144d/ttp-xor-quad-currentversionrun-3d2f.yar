rule TTP_XOR_QUAD_CurrentVersionRun_3d2f {
  strings:
    $key_3d2f = { 6e 40 [2] 4a 4e [2] 61 62 [2] 4f 40 [2] 5b 5b [2] 54 41 [2] 4a 5c [2] 48 5d [2] 53 5b [2] 4f 5c [2] 53 73 }

  condition:
    any of them
}