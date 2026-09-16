rule TTP_XOR_QUAD_CurrentVersionRun_272f {
  strings:
    $key_272f = { 74 40 [2] 50 4e [2] 7b 62 [2] 55 40 [2] 41 5b [2] 4e 41 [2] 50 5c [2] 52 5d [2] 49 5b [2] 55 5c [2] 49 73 }

  condition:
    any of them
}