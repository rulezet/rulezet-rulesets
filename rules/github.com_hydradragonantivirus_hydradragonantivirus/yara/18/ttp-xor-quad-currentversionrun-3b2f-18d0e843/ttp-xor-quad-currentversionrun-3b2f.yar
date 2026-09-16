rule TTP_XOR_QUAD_CurrentVersionRun_3b2f {
  strings:
    $key_3b2f = { 68 40 [2] 4c 4e [2] 67 62 [2] 49 40 [2] 5d 5b [2] 52 41 [2] 4c 5c [2] 4e 5d [2] 55 5b [2] 49 5c [2] 55 73 }

  condition:
    any of them
}