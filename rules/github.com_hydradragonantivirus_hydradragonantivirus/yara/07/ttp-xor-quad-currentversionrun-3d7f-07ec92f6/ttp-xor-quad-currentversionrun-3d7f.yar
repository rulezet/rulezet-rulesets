rule TTP_XOR_QUAD_CurrentVersionRun_3d7f {
  strings:
    $key_3d7f = { 6e 10 [2] 4a 1e [2] 61 32 [2] 4f 10 [2] 5b 0b [2] 54 11 [2] 4a 0c [2] 48 0d [2] 53 0b [2] 4f 0c [2] 53 23 }

  condition:
    any of them
}