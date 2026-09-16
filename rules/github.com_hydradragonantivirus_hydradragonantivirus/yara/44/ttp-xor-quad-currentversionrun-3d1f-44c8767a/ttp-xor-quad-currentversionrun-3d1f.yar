rule TTP_XOR_QUAD_CurrentVersionRun_3d1f {
  strings:
    $key_3d1f = { 6e 70 [2] 4a 7e [2] 61 52 [2] 4f 70 [2] 5b 6b [2] 54 71 [2] 4a 6c [2] 48 6d [2] 53 6b [2] 4f 6c [2] 53 43 }

  condition:
    any of them
}