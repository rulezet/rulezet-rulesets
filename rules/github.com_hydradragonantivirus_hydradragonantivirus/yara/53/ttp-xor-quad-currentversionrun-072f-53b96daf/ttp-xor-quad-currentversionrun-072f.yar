rule TTP_XOR_QUAD_CurrentVersionRun_072f {
  strings:
    $key_072f = { 54 40 [2] 70 4e [2] 5b 62 [2] 75 40 [2] 61 5b [2] 6e 41 [2] 70 5c [2] 72 5d [2] 69 5b [2] 75 5c [2] 69 73 }

  condition:
    any of them
}