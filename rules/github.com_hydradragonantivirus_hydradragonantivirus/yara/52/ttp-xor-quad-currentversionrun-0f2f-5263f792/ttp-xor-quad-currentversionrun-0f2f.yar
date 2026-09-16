rule TTP_XOR_QUAD_CurrentVersionRun_0f2f {
  strings:
    $key_0f2f = { 5c 40 [2] 78 4e [2] 53 62 [2] 7d 40 [2] 69 5b [2] 66 41 [2] 78 5c [2] 7a 5d [2] 61 5b [2] 7d 5c [2] 61 73 }

  condition:
    any of them
}