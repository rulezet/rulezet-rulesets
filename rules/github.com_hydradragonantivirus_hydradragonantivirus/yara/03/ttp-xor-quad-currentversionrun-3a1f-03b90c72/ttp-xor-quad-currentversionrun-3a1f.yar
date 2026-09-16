rule TTP_XOR_QUAD_CurrentVersionRun_3a1f {
  strings:
    $key_3a1f = { 69 70 [2] 4d 7e [2] 66 52 [2] 48 70 [2] 5c 6b [2] 53 71 [2] 4d 6c [2] 4f 6d [2] 54 6b [2] 48 6c [2] 54 43 }

  condition:
    any of them
}