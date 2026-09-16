rule TTP_XOR_QUAD_CurrentVersionRun_3a2f {
  strings:
    $key_3a2f = { 69 40 [2] 4d 4e [2] 66 62 [2] 48 40 [2] 5c 5b [2] 53 41 [2] 4d 5c [2] 4f 5d [2] 54 5b [2] 48 5c [2] 54 73 }

  condition:
    any of them
}