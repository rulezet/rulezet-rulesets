rule TTP_XOR_QUAD_CurrentVersionRun_262f {
  strings:
    $key_262f = { 75 40 [2] 51 4e [2] 7a 62 [2] 54 40 [2] 40 5b [2] 4f 41 [2] 51 5c [2] 53 5d [2] 48 5b [2] 54 5c [2] 48 73 }

  condition:
    any of them
}